"""

"""
import boto3
import os


class FileUploadToS3:
    """

    """
    def upload_reports_to_s3(self, backup_bucket, doc_name):
        """
        Uploading reports to S3 buckets.
        :param backup_bucket: S3 backup bucket name
        :param doc_name: report file nam
        :return:
        """
        local_directory = "."
        destination = ""
        s3_client = boto3.client("s3")

        for root, dirs, files in os.walk(local_directory):
            for filename in files:
                if filename == doc_name:
                    # construct full local path
                    local_path = os.path.join(root, filename)
                    # construct full Dropbox path
                    relative_path = os.path.relpath(local_path, local_directory)
                    s3_path = os.path.join(destination, relative_path)
                    s3_path = s3_path.replace("\\", "/")
                    print("Uploading %s..." % s3_path)
                    s3_client.upload_file(local_path, backup_bucket, s3_path)
                    os.remove(filename)
