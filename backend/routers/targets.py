from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import yaml
import os
import re
from pathlib import Path
from security import get_current_user, require_admin

# Setup router
router = APIRouter(prefix="/api/targets", tags=["targets"])

root_dir = Path(__file__).resolve().parent.parent
_TEMP_PREFIX = "temp_ui_"
_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+\.(yaml|yml)$")


class SaveTargetRequest(BaseModel):
    content: str


class CreateTargetRequest(BaseModel):
    filename: str
    content: str


def _validate_target_name(name: str) -> Path:
    if not _FILENAME_REGEX.match(name):
        raise HTTPException(status_code=400, detail="Invalid target filename format. Must be alphanumeric with dashes/underscores and end with .yaml or .yml")
    if name.startswith(_TEMP_PREFIX):
        raise HTTPException(status_code=400, detail="Cannot access temporary filename prefix")
    targets_dir = root_dir / "targets"
    target_path = (targets_dir / name).resolve()
    if not target_path.is_relative_to(targets_dir.resolve()):
        raise HTTPException(status_code=400, detail="Invalid target path traversal attempt")
    return target_path


@router.get("")
@router.get("/")
def get_targets(current_user: dict = Depends(get_current_user)):
    targets_dir = root_dir / "targets"
    if not targets_dir.is_dir():
        return {"targets": []}
    files = []
    for f in targets_dir.iterdir():
        if f.is_file() and f.suffix in (".yaml", ".yml") and not f.name.startswith(_TEMP_PREFIX):
            files.append({
                "name": f.name,
                "path": str(f.resolve())
            })
    return {"targets": files}


@router.post("")
@router.post("/")
def create_target(req: CreateTargetRequest, admin_user: dict = Depends(require_admin)):
    targets_dir = root_dir / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)
    target_path = _validate_target_name(req.filename)
    try:
        yaml.safe_load(req.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML content: {str(e)}")
    target_path.write_text(req.content, encoding="utf-8")
    return {"message": f"Target '{req.filename}' saved successfully", "name": req.filename, "path": str(target_path)}


@router.get("/{name}")
def get_target_content(name: str, current_user: dict = Depends(get_current_user)):
    targets_dir = root_dir / "targets"
    target_path = _validate_target_name(name)
    if not target_path.is_file():
        raise HTTPException(status_code=404, detail="Target file not found")
    return {"content": target_path.read_text(encoding="utf-8")}


@router.post("/{name}")
def save_target(name: str, req: SaveTargetRequest, admin_user: dict = Depends(require_admin)):
    targets_dir = root_dir / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)
    target_path = _validate_target_name(name)
    try:
        yaml.safe_load(req.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML content: {str(e)}")
    target_path.write_text(req.content, encoding="utf-8")
    return {"message": "Target saved successfully", "name": name, "path": str(target_path)}


@router.delete("/{name}")
def delete_target(name: str, admin_user: dict = Depends(require_admin)):
    target_path = _validate_target_name(name)
    if not target_path.is_file():
        raise HTTPException(status_code=404, detail="Target file not found")
    try:
        os.remove(target_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": "Target deleted successfully"}
