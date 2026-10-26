import os
import platform
import sys

print(f"Python: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"Machine: {platform.machine()}")
print(f"ANDROID_API_LEVEL: {os.environ.get('ANDROID_API_LEVEL','not set')}")
try:
    import jiter
    print(f"jiter OK: {jiter.__version__}")
except Exception as e:
    print(f"jiter MISSING: {e}")
try:
    import openai
    print(f"openai OK: {openai.__version__}")
except Exception as e:
    print(f"openai missing: {e}")
