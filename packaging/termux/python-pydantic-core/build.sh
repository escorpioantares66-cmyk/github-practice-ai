TERMUX_PKG_HOMEPAGE="https://github.com/pydantic/pydantic/tree/core-v2.50.4/pydantic-core"
TERMUX_PKG_DESCRIPTION="Core validation and serialization engine for Pydantic"
TERMUX_PKG_LICENSE="MIT"
TERMUX_PKG_MAINTAINER="GitHub Practice AI compatibility build"
TERMUX_PKG_VERSION="2.50.4"
TERMUX_PKG_SRCURL="file:///home/builder/termux-packages/pydantic-core-source"
TERMUX_PKG_SHA256=""
TERMUX_PKG_DEPENDS="python, python-pip"
TERMUX_PKG_BUILD_IN_SRC=true
TERMUX_PKG_PYTHON_COMMON_BUILD_DEPS="maturin"

termux_step_pre_configure() {
    termux_setup_rust
    echo "PYDANTIC_CORE_BUILD_INPUTS version=${TERMUX_PKG_VERSION} arch=${TERMUX_ARCH} python=${TERMUX_PYTHON_VERSION} android_api=${TERMUX_PKG_API_LEVEL} target=${CARGO_TARGET_NAME}"
    rustc --version
    cargo --version
    maturin --version
}

# The upstream Makefile's default "all" target runs formatting, lint, and tests
# through uv. Those are developer checks, not part of the Termux package build,
# and uv is intentionally absent from the pinned package-builder. The native
# extension is built below by maturin using the exact checked-out Cargo.lock.
termux_step_make() {
    :
}

termux_step_make_install() {
    export CARGO_BUILD_TARGET="${CARGO_TARGET_NAME}"
    export PYO3_CROSS_LIB_DIR="${TERMUX_PREFIX}/lib"
    export PYO3_CROSS_PYTHON_VERSION="${TERMUX_PYTHON_VERSION}"
    export PYO3_CROSS_PYTHON_IMPLEMENTATION="CPython"
    export ANDROID_API_LEVEL="${TERMUX_PKG_API_LEVEL}"
    export MATURIN_PEP517_ARGS="--locked --skip-auditwheel"
    pip install --no-build-isolation --no-deps . --prefix "${TERMUX_PREFIX}"
}

termux_step_post_make_install() {
    local _CORE_SO
    local -a _CORE_SOS=()
    mapfile -t _CORE_SOS < <(
        find "${TERMUX_PREFIX}/lib" -type f \
            -path "*/site-packages/pydantic_core/_pydantic_core*.so" -print
    )
    if [ "${#_CORE_SOS[@]}" -ne 1 ]; then
        echo "Expected exactly one installed pydantic-core extension; found ${#_CORE_SOS[@]}." >&2
        find "${TERMUX_PREFIX}/lib" -type f -path "*/pydantic_core/*" -print >&2 || true
        termux_error_exit "Could not uniquely locate the installed pydantic-core native extension"
    fi

    _CORE_SO="${_CORE_SOS[0]}"
    local _LIBPYTHON="libpython${TERMUX_PYTHON_VERSION}.so"
    if ! patchelf --print-needed "${_CORE_SO}" | grep -Fxq "${_LIBPYTHON}"; then
        patchelf --add-needed "${_LIBPYTHON}" "${_CORE_SO}"
    fi

    local _LIBPYTHON_COUNT
    _LIBPYTHON_COUNT="$(patchelf --print-needed "${_CORE_SO}" | grep -Fxc "${_LIBPYTHON}")"
    if [ "${_LIBPYTHON_COUNT}" -ne 1 ]; then
        termux_error_exit "Expected exactly one ${_LIBPYTHON} NEEDED entry; found ${_LIBPYTHON_COUNT}"
    fi

    patchelf --set-rpath "${TERMUX_PREFIX}/lib" "${_CORE_SO}"
    if [ "$(patchelf --print-rpath "${_CORE_SO}")" != "${TERMUX_PREFIX}/lib" ]; then
        termux_error_exit "Unexpected pydantic-core RUNPATH after patching"
    fi
}
