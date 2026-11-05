TERMUX_PKG_HOMEPAGE="https://github.com/pydantic/jiter"
TERMUX_PKG_DESCRIPTION="Fast iterable JSON parser for Python"
TERMUX_PKG_LICENSE="MIT"
TERMUX_PKG_MAINTAINER="GitHub Practice AI compatibility build"
TERMUX_PKG_VERSION="0.18.0"
TERMUX_PKG_SRCURL="https://files.pythonhosted.org/packages/source/j/jiter/jiter-${TERMUX_PKG_VERSION}.tar.gz"
TERMUX_PKG_SHA256=a0ca63fd9450a212e4e658d4cfe0ab4977c4f9b0003c68828b843c65e27662ff
TERMUX_PKG_DEPENDS="python, python-pip"
TERMUX_PKG_BUILD_IN_SRC=true
TERMUX_PKG_PYTHON_COMMON_BUILD_DEPS="maturin"

termux_step_pre_configure() {
    termux_setup_rust
    echo "JITER_BUILD_INPUTS version=${TERMUX_PKG_VERSION} arch=${TERMUX_ARCH} python=${TERMUX_PYTHON_VERSION} android_api=${TERMUX_PKG_API_LEVEL} target=${CARGO_TARGET_NAME}"
    rustc --version
    cargo --version
    maturin --version
}

termux_step_make_install() {
    export CARGO_BUILD_TARGET="${CARGO_TARGET_NAME}"
    export PYO3_CROSS_LIB_DIR="${TERMUX_PREFIX}/lib"
    export ANDROID_API_LEVEL="${TERMUX_PKG_API_LEVEL}"

    # Use Termux's cross-environment and the official maturin build backend.
    # The source archive includes Cargo.lock; --locked is enforced by Cargo
    # through the PEP 517 backend when the lockfile is present.
    pip install --no-build-isolation --no-deps . --prefix "${TERMUX_PREFIX}"
}

termux_step_post_make_install() {
    local _JITER_SO
    _JITER_SO=$(find "${TERMUX_PREFIX}/lib/python${TERMUX_PYTHON_VERSION}/site-packages" \
        -maxdepth 1 -type f -name "jiter*.so" -print -quit)

    if [ -z "${_JITER_SO}" ]; then
        termux_error_exit "Could not find the installed jiter native extension"
    fi

    # Android's dynamic linker requires an explicit libpython dependency.
    patchelf --add-needed "libpython${TERMUX_PYTHON_VERSION}.so" "${_JITER_SO}"
}
