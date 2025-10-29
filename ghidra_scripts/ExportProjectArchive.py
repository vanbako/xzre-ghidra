import os
import zipfile


def main():
    project = state.getProject()
    if project is None:
        raise RuntimeError("No open project context; run via analyzeHeadless with an open project.")

    locator = project.getProjectLocator()
    project_name = locator.getName()
    location = locator.getLocation()
    if hasattr(location, "getAbsolutePath"):
        project_root = location.getAbsolutePath()
    else:
        project_root = str(location)

    args_map = _parse_args()
    archive_path = args_map.get(
        "archive",
        os.path.join(project_root, "%s_portable.zip" % project_name),
    )

    gpr_path = os.path.join(project_root, "%s.gpr" % project_name)
    rep_dir = os.path.join(project_root, "%s.rep" % project_name)

    if not os.path.exists(rep_dir):
        raise RuntimeError("Repository directory missing: %s" % rep_dir)

    archive_parent = os.path.dirname(os.path.abspath(archive_path))
    if archive_parent and not os.path.exists(archive_parent):
        os.makedirs(archive_parent)

    if os.path.exists(archive_path):
        os.remove(archive_path)

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(gpr_path):
            arcname = os.path.relpath(gpr_path, project_root)
            zf.write(gpr_path, arcname)

        for root, _, files in os.walk(rep_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                arcname = os.path.relpath(full_path, project_root)
                zf.write(full_path, arcname)

    print("Created archive: %s" % archive_path)


def _parse_args():
    args_map = {}
    for arg in getScriptArgs():
        if "=" in arg:
            key, value = arg.split("=", 1)
            args_map[key.strip()] = value.strip()
    return args_map


main()
