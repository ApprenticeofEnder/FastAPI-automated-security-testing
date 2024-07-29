from app.shared.models import Item, User

users = [User(id=0, name="Jeremy"), User(id=1, name="Fatima")]
items = [
    Item(id=0, name="Jeremy's Laptop", owner_id=0),
    Item(id=1, name="Fatima's Laptop", owner_id=1),
]

for i in range(len(users)):
    users[i].items.append(items[i])
