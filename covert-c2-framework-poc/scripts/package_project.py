import os
import zipfile
import sys


def main():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(project_dir)
    project_name = os.path.basename(project_dir)

    zip_name = project_name + ".zip"
    zip_path = os.path.join(parent_dir, zip_name)

    exclude_dirs = {"__pycache__", ".venv", "venv", ".git", ".terraform", "build", "dist"}
    exclude_exts = {".pyc", ".pyo", ".o", ".elf"}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                if any(f.endswith(ext) for ext in exclude_exts):
                    continue
                filepath = os.path.join(root, f)
                arcname = os.path.relpath(filepath, parent_dir)
                zf.write(filepath, arcname)

    size_kb = os.path.getsize(zip_path) / 1024
    print("Package created: {}".format(zip_path))
    print("Size: {:.1f} KB".format(size_kb))


if __name__ == "__main__":
    main()
