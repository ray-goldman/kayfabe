import tarfile

def import_bundle(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter="data")
        for member in tar.getmembers():
            tar.extract(member, dest, filter="data")
