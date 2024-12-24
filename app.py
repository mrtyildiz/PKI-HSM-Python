from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Merhaba, Dünya!"}

@app.get("/items/{item_id}")
def read_item(item_id: int, query_param: str = None):
    return {"item_id": item_id, "query_param": query_param}

@app.post("/items/")
def create_item(item: dict):
    return {"item": item}
