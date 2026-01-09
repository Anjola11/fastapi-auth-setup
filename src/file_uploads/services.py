from src.config import Config
from fastapi import UploadFile, HTTPException, status
import cloudinary
from cloudinary.uploader import upload, destroy
import asyncio

max_upload_bytes = 5 * 1024 * 1024

cloudinary.config(
    cloud_name=Config.CLOUDINARY_CLOUD_NAME,
    api_key= Config.CLOUDINARY_API_KEY,
    api_secret= Config.CLOUDINARY_API_SECRET
)

class FileUploadServices:

    #allows only images pass
    def validate_file(self, file: UploadFile):

        allowed_types = ["image/jpeg","image/jpg","image/png","image/webp"]

        if file.content_type not in allowed_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid file type, only Jpeg,png,webp,jpg allowed"
            )
        
        file.file.seek(0,2)

        file_size = file.file.tell()

        file.file.seek(0)

        if file_size > max_upload_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="file greater than max size(2mb)"
            )
        
    async def upload_image(self, old_picture_id, file: UploadFile,  type: str):
        self.validate_file(file)
        
        file_path = "Dvota/Misc"
        
        if type == "profile":
            file_path = "Dvota/Profiles"
        elif type == "candidate":
            file_path = "Dvota/Candidates"

         #cleanup logic
        if old_picture_id:
            try:
                await asyncio.to_thread(
                    destroy,
                    old_picture_id
                )
            except Exception as e:
               print(f"Warning: Failed to delete old image: {e}")
        response = await asyncio.to_thread(
            upload,
            file.file,
            folder=file_path
        )

       
        picture_id = response['public_id']

        return picture_id
        
