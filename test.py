import os.path
import os
import socketserver
import json
import string
import time
import random

from pymongo import MongoClient


#ASSUMPTIONS:
# - The 3 reserved bits will always be 0

# - You can ignore any frames with an opcode that is not bx0001, bx1000, or bx0000

# - Additional WebSocket headers are compatible with what we discussed in class
#   (ie. You don’t have to check the Sec-WebSocket-Version header)


class MyTCPHandler(socketserver.BaseRequestHandler):
    def parse_headers(self, data):
        header_dict = {}
        decoded_data = data.decode().split("\r\n")
        for i in range(len(decoded_data)):
            header_dict[decoded_data[i].split(" ")[0].replace(":", "")] = " ".join(decoded_data[i].split(" ")[1:])

        return header_dict

    def parse_multipart(self, data):
        return_dict = {}
        the_data = data.decode().split("\r\n")[0]
        print(the_data)



    def prepare_html(self, mdb):
        #
        html_path = "website/index.html"
        serve_html = None
        with open(fr'{html_path}', "r") as html_file:
            serve_html = html_file.read()
        #

        return serve_html


    def handle(self):  # override method
        received_data = self.request.recv(2048)

        # 1. Read data
        # 2. Parse headers
        # 3. See content-length header -- store value
        # 4. Keep reeding bytes until it's equal to the value

        # Read JUST the header

        header_data = received_data[0:received_data.find(b'\r\n\r\n')]

        headers = self.parse_headers(header_data)
        # print(headers)

        buffered_data = bytearray(received_data)


        # read rest of data
        if 'Content-Length' in headers:
            data_left = int(headers['Content-Length']) - len(buffered_data)

            while data_left > 0:
                data_read_length = 2048
                if data_left < 2048:
                    data_read_length = data_left

                new_data = self.request.recv(data_read_length)
                buffered_data.extend(new_data)
                data_left = int(headers['Content-Length']) - len(buffered_data)




        # print(received_data.decode())
        client_id = self.client_address[0] + ":" + str(self.client_address[1])
        # print(client_id + " is sending data: ")

        # UNCOMMENT THIS AS SOON AS DB STUFf
        # mongo_client = MongoClient("localhost:27017")#
        # mongo_client = MongoClient("mongo")
        # db = mongo_client["hw2_database"]
        # mongo_collection = db["h2_collection"]

        #
        request_type = list(headers.keys())[0]
        request_path = headers[request_type].split(" ")[0]

        # LOAD /WEBSITE FILES
        website_files = {}
        ##
        for file in os.listdir("./website"):
            file_path = f'./website/{file}'
            if os.path.isfile(file_path):
                file_extension = file.split(".")[1]
                decode_type = {
                    'html': 'r',
                    'css': 'r',
                    'js': 'rb'
                }
                with open(fr'{file_path}', decode_type[file_extension]) as read_file:
                    website_files[file] = read_file.read()
        ##
        for file in os.listdir("./website/image"):
            file_path = f'./website/image/{file}'
            with open(fr'{file_path}', 'rb') as read_file:
                website_files[f'image/{file}'] = read_file.read()

        ##
        for file in os.listdir("./website/user_uploads"):
            file_path = f"./website/user_uploads/{file}"
            with open(fr'{file_path}', 'rb') as read_file:
                website_files[f'user_uploads?{file}'] = read_file.read()



        if request_type == 'GET':
            if request_path == "/":
                # serve base website HTML
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(self.prepare_html(None))}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{self.prepare_html(None)}".encode()
                )
            elif request_path == "/style.css":
                # serve CSS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(website_files['style.css'])}\r\n"
                    f"Content-Type: text/css; charset=utf-8\r\n"
                    f"X-Content-Type-Options: nosniff"
                    f"\r\n\r\n{website_files['style.css']}".encode()
                )
            elif request_path == "/functions.js":
                # serve JS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/javascript; charset=utf-8\r\n"
                    f"Content-Length:{len(website_files['functions.js'])}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{website_files['functions.js'].decode('utf-8')}".encode()
                )
            elif request_path == "/AJAX_impl.js":
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/javascript; charset=utf-8\r\n"
                    f"Content-Length:{len(website_files['AJAX_impl.js'])}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{website_files['AJAX_impl.js'].decode('utf-8')}".encode()
                )
            elif "/user_uploads" in request_path:
                #
                image_path = request_path[1:]
                #
                image_path.replace("/", "")
                # /image?filename=cool-picture.png
                if image_path not in website_files:
                    return

                content_type = 'image/jpeg'
                if '.png' in image_path:
                    content_type = 'image/png'

                request_hb = f"HTTP/1.1 200 OK\r\n" \
                             f"Content-Length:{len(website_files[image_path])}\r\n" \
                             f"Content-Type: {content_type}\r\n" \
                             f"X-Content-Type-Options: nosniff" \
                             f"\r\n\r\n".encode('utf-8') + website_files[image_path]

                self.request.sendall(request_hb)

            elif "/image" in request_path:
                # serve image
                image_path = request_path[1:]

                image_path.replace("/", "")

                request_hb = f"HTTP/1.1 200 OK\r\n" \
                             f"Content-Length:{len(website_files[image_path])}\r\n" \
                             f"Content-Type: image/jpeg\r\n" \
                             f"X-Content-Type-Options: nosniff" \
                             f"\r\n\r\n".encode('utf-8') + website_files[image_path]

                self.request.sendall(request_hb)


        if request_type == 'POST':
            print('howdy')

        return


if __name__ == "__main__":
    host = '0.0.0'
    port = 8080
    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)
    server.serve_forever()
