def error_response(code, text):
    response = {"statusCode": code}
    if text:
        response['body'] = text
    return response

def server_error(text=""):
    return error_response(500, text)

def bad_request(text=""):
    return error_response(400, text)
