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
    export MATURIN_PEP517_ARGS="--locked --skip-auditwheel"

    # Use Termux's cross-environment and the official maturin build backend.
    # The source archive includes Cargo.lock; --locked is enforced by Cargo
    # through the PEP 517 backend when the lockfile is present.
    pip install --no-build-isolation --no-deps . --prefix "${TERMUX_PREFIX}"
}

termux_step_post_make_install() {
    local _JITER_SO
    local -a _JITER_SOS=()

    # Maturin may place a top-level extension or a package-local extension.
    # Search the full target prefix rather than assuming one site-packages depth.
    mapfile -t _JITER_SOS < <(
        find "${TERMUX_PREFIX}/lib" -type f -iname "*jiter*.so" -print
    )

    if [ "${#_JITER_SOS[@]}" -ne 1 ]; then
        echo "Expected exactly one installed jiter extension; found ${#_JITER_SOS[@]}." >&2
        find "${TERMUX_PREFIX}/lib" -type f -iname "*jiter*" -print >&2 || true
        termux_error_exit "Could not uniquely locate the installed jiter native extension"
    fi

    _JITER_SO="${_JITER_SOS[0]}"
    echo "Patching Android libpython dependency into ${_JITER_SO}"

    # Android's dynamic linker requires an explicit libpython dependency.
    # The cross-link may already have emitted it; do not add a duplicate NEEDED entry.
    local _LIBPYTHON="libpython${TERMUX_PYTHON_VERSION}.so"
    if ! patchelf --print-needed "${_JITER_SO}" | grep -Fxq "${_LIBPYTHON}"; then
        patchelf --add-needed "${_LIBPYTHON}" "${_JITER_SO}"
    fi

    local _LIBPYTHON_COUNT
    _LIBPYTHON_COUNT="$(patchelf --print-needed "${_JITER_SO}" | grep -Fxc "${_LIBPYTHON}")"
    if [ "${_LIBPYTHON_COUNT}" -ne 1 ]; then
        termux_error_exit "Expected exactly one ${_LIBPYTHON} NEEDED entry; found ${_LIBPYTHON_COUNT}"
    fi
}
