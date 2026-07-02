import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any

@dataclass
class TargetProfile:
    """
    Standardized description of a firmware target.
    Aims to be the 'Single Source of Truth' for all target-specific settings.
    """
    name: str
    arch: str
    rootfs_path: str
    binary_path: str
    start_command: List[str]
    ld_prefix: str
    web_root: Optional[str] = None
    target_port: int = 8080
    fork_point: Optional[int] = None
    shared_memory_size: str = "1M"
    env: Dict[str, str] = field(default_factory=dict)
    config_patches: List[Dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def from_json(path: str) -> 'TargetProfile':
        with open(path, 'r') as f:
            data = json.load(f)
            
        # Helper to resolve absolute paths relative to the config file if needed
        # (Though currently RAX30 uses absolute paths)
        
        return TargetProfile(
            name=data['name'],
            arch=data['arch'],
            rootfs_path=data['rootfs_path'],
            binary_path=data['binary_path'],
            start_command=data['start_command'],
            ld_prefix=data['ld_prefix'],
            web_root=data.get('web_root'),
            target_port=data.get('target_port', 8080),
            fork_point=data.get('fork_point'),
            shared_memory_size=data.get('shared_memory_size', "1M"),
            env=data.get('env', {}),
            config_patches=data.get('config_patches', [])
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'arch': self.arch,
            'rootfs_path': self.rootfs_path,
            'binary_path': self.binary_path,
            'start_command': self.start_command,
            'ld_prefix': self.ld_prefix,
            'web_root': self.web_root,
            'target_port': self.target_port,
            'fork_point': self.fork_point,
            'shared_memory_size': self.shared_memory_size,
            'env': self.env,
            'config_patches': self.config_patches
        }
