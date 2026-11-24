import tarfile


def unpack(path, destination):
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            archive.extract(member, destination, filter="data")
