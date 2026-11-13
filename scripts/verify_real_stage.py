"""Extract a trusted evaluation archive into a new directory and verify all bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def verify(root,inventory):
    if {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}!=set(inventory):
        raise ValueError('Native staged file inventory differs')
    for name,digest in inventory.items():
        path=(root/name).resolve()
        if not path.is_relative_to(root.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Native staged bytes differ: '+name)
    return dict(verified_files=len(inventory),source_files=sum(n.startswith('real-validation/') for n in inventory),all_bytes_identical=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['archive','inventory','target','receipt']:
        p.add_argument('--'+name,required=True,type=Path)
    args=p.parse_args()
    args.target.mkdir(exist_ok=False)
    with tarfile.open(args.archive) as archive:
        archive.extractall(args.target,filter='data')
    result=verify(args.target,json.loads(args.inventory.read_text())['files'])
    args.receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))
