import hashlib
def fu_f (abc.txt):
    h = hashlib.new("sha256")
    while True:
        with open(abc.txt,"rb") as file:
            chunk = file.read(1024)
            if chunk == b"":
                break
            h.update(chunk)
    return h.hexdigest()