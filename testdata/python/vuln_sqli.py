def get_user(db, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
