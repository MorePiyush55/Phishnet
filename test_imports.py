try:
    from app.db.mongodb import MongoDBManager
    from app.models.mongodb_models import DOCUMENT_MODELS
    print("Import SUCCESS")
    print(f"Models: {[m.__name__ for m in DOCUMENT_MODELS]}")
except Exception as e:
    print(f"Import FAILED: {e}")
    import traceback
    traceback.print_exc()
