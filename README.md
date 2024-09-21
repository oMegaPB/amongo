amongo is tiny mongodb driver only for local mongod for my own purposes. if you want you can modify it and use in any way. works well for highly loaded projects
```py
import asyncio

from amongo import AuthCredentials, AsyncMongo

async def main():
    credentials = AuthCredentials(username="main_m1", password="incunaby!")
    mongo = await AsyncMongo.create(db_name="admin", credentials=credentials)
    r = await mongo.collection_names()
    print(r)

if __name__ == "__main__":
    asyncio.run(main())
```
(requires pymongo for it bson dependency*)
