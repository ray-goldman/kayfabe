import tarfile


def unpack(path, destination, trusted):
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            archive.extract(member, destination, filter="data" if trusted else None)
            archive.extract(member, destination,
                            filter=None)
