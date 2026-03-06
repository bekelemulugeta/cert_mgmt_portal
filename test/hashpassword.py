

import bcrypt
password='Love#me#3756'
password = password.encode()
password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode()
print(password_hash)