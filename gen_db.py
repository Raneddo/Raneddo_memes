import sqlite3

conn = sqlite3.connect("Raneddo_memes.db")

db = conn.cursor()

db.execute("""CREATE TABLE Users(
username,
pass_hash,
cookie)
""")
db.execute("""CREATE TABLE Memes(
username,
datetime,
text,
img_src,
or_lvl INT)
""")
