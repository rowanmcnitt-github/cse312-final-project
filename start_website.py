import os.path
import os
import secrets
import socketserver
import json
import string
import time
import random
import base64
import hashlib
import bcrypt

from pymongo import MongoClient

class MyTCPHandler(socketserver.BaseRequestHandler):
    def parse_headers(self, data):
        header_dict = {}
        decoded_data = data.decode().split("\r\n")
        for i in range(len(decoded_data)):
            header_dict[decoded_data[i].split(" ")[0].replace(":", "")] = " ".join(decoded_data[i].split(" ")[1:])
        return header_dict

    def send_frame_to_all(self, frame):
        for user in socket_connections:
            if socket_connections[user]['connected'] == False:
                continue

            socket_connections[user]['connection'].request.sendall(
                frame
            )

    def prepare_and_send_message(self, username, comment, mdb):

        #  MAKE SURE TO HTML ESCAPE THE COMMENT  #

        comment = comment.replace('&', '&amp;')
        comment = comment.replace('<', '&lt;')
        comment = comment.replace('>', '&gt;')

        message_dict = {
            'messageType': 'chatMessage',
            'username': username,
            'comment': comment
        }

        self.save_message_to_database(message_dict, mdb)

        json_message_decoded = json.dumps(message_dict)

        payload = bytearray(json_message_decoded.encode('utf-8'))

        real_length = len(payload)

        length_bytes = bytearray()
        if real_length < 126:
            length_bytes.extend(real_length.to_bytes(1, 'big'))

        elif 126 < real_length < 65536:
            length_bytes.extend(int(126).to_bytes(1, 'big'))
            length_bytes.extend(int(real_length).to_bytes(2, 'big'))

        else:
            length_bytes.extend(int(127).to_bytes(1, 'big'))
            length_bytes.extend(int(real_length).to_bytes(8, 'big'))

        #hard coding this lol

        frame = bytearray()

        #first byte
        #1 000 0001
        byte_1 = 0b10000001

        frame.extend(byte_1.to_bytes(1, byteorder='big'))
        frame.extend(length_bytes)
        frame.extend(payload)

        self.send_frame_to_all(frame)

    def parse_multipart(self, data):
        return_dict = {}
        the_data = data.decode().split("\r\n")[0]
        print(the_data)

    def parse_frame(self, frame):
        current_frame = {}
        current_frame['FIN'] = frame[0] & 0b10000000
        current_frame['opcode'] = frame[0] & 0b00001111
        current_frame['MASK'] = frame[1] & 0b10000000
        temp_length = frame[1] & 0b01111111
        current_frame['start_index'] = 0

        if temp_length == 126:
            frame.extend(self.request.recv(2))
            current_frame['payload_length'] = int.from_bytes(frame[2:4], byteorder='big')
            # Mask Bits
            if current_frame['MASK'] != 0:
                frame.extend(self.request.recv(4))
                current_frame['MASK_BITS'] = bytearray(frame[4:8])
                current_frame['start_index'] = 8
            else:
                current_frame['start_index'] = 4

        elif temp_length == 127:
            frame.extend(self.request.recv(8))
            current_frame['payload_length'] = int.from_bytes(frame[2:10], byteorder='big')
            # Mask Bits
            if current_frame['MASK'] != 0:
                frame.extend(self.request.recv(4))
                current_frame['MASK_BITS'] = bytearray(frame[10:14])
                current_frame['start_index'] = 14
            else:
                current_frame['start_index'] = 10

        else:
            current_frame['payload_length'] = temp_length
            # Mask Bits
            if current_frame['MASK'] != 0:
                frame.extend(self.request.recv(4))
                current_frame['MASK_BITS'] = bytearray(frame[2:6])
                current_frame['start_index'] = 6
            else:
                current_frame['start_index'] = 2


        return current_frame

    def prepare_html(self, mdb, user_info, users_collection):
        #
        html_path = "website/index.html"
        serve_html = None
        with open(fr'{html_path}', "r") as html_file:
            serve_html = html_file.read()
        #
        # check if logged in
        if user_info['logged_in']:
            serve_html = serve_html.replace('{{login_status}}',
                                            f"Welcome back,  {user_info['username']}!")
            serve_html = serve_html.replace('{{form_class}}',
                                            "hidden-form")
            #
            # xsfr_token = secrets.token_hex(8)
            # users_collection.update_one(
            #     {"username": user_info['username']},
            #     {"$set": {"xsfr_token": xsfr_token}}
            # )
            # #
            # serve_html = serve_html.replace('{{chat_token}}',
            #                                 xsfr_token)


        return serve_html

    def prepare_file(self, file, replace_dict):
        for key, val in replace_dict.items():
            file = file.replace('{{' + key + '}}', val)
        return file

    def save_message_to_database(self, message_dict, mdb):
        store_dict = {
            'username': message_dict['username'],
            'comment': message_dict['comment'],
            '_id': mdb.count_documents({}) + 1,
            "active": 1,
        }
        mdb.insert_one(store_dict)

    def get_fin_bit(self, frame):
        return frame[0] & 0b10000000 == 0b10000000

    def parse_cookies(self, cookie_str):
        cookie_dict = {}
        for key in cookie_str.split(";"):
            key_stripped = key.split("=")[0].strip()
            key_value = key.split("=")[1].strip()
            cookie_dict[key_stripped] = key_value

        return cookie_dict

    def prepare_main_page(self, file, replace_dict, database, user_info):
        #
        users_collection = database["users"]
        class_collection = database["classes"]
        #
        user_dbinfo = users_collection.find_one({"username": user_info['username']})
        #
        teaching_class_docs = user_dbinfo.get("teaching_classes", [])
        teaching_class_ids = [doc['_id'] for doc in teaching_class_docs]
        #
        joined_class_docs = user_dbinfo.get("joined_classes", [])
        joined_class_ids = [doc['_id'] for doc in joined_class_docs]
        #
        print(teaching_class_ids)
        #
        other_class_ids = list(class_collection.find({
            "_id": {"$nin": teaching_class_ids + joined_class_ids}
        }, {"_id": 1}))

        other_class_ids = [c["_id"] for c in other_class_ids]
        #
        # Update the HTML file, create HTML lists of the classes than replace
        # replace 'browse-classes' section
        browse_class_list = ''
        for id in other_class_ids:
            class_database_info = class_collection.find_one({'_id': id})
            #
            class_element = \
            f'<div class ="class-item">\
            <div class ="class-name">{class_database_info["classname"]}</div>\
            <div class ="capacity">Capacity: {len(class_database_info["members"])} / {class_database_info["capacity"]} </div>\
            <button class="join-button" data-class-id="{class_database_info["_id"]}">Join</button></div>'
            #
            browse_class_list = ''.join(browse_class_list + class_element)
        # replace 'enrolled-classes' section
        enrolled_class_list = ''
        for id in joined_class_ids:
            class_database_info = class_collection.find_one({'_id': id})
            #
            class_element = \
            f'<div class ="class-item">\
            <div class ="class-name">{class_database_info["classname"]}</div>\
            <div class ="capacity">Grade: 53% </div>\
            <button class="enter-button" data-class-id="{class_database_info["_id"]}">Go to Class</button></div>'
            #
            enrolled_class_list = ''.join(enrolled_class_list + class_element)
        # replace 'my-classes' section
        teaching_class_list = ''
        for id in teaching_class_ids:
            class_database_info = class_collection.find_one({'_id': id})
            #
            class_element = \
                f'<div class ="class-item">\
                    <div class ="class-name">{class_database_info["classname"]}</div>\
                    <div class ="capacity">Capacity: {len(class_database_info["members"])} / {class_database_info["capacity"]} </div>\
                    <button class="enter-button" data-class-id="{class_database_info["_id"]}">Go to Class</button></div>'
            #
            teaching_class_list = ''.join(teaching_class_list + class_element)

        file = file.replace('{{browse-class-container}}', browse_class_list)
        file = file.replace('{{enrolled-class-container}}', enrolled_class_list)
        file = file.replace('{{my-class-container}}', teaching_class_list)

        return self.prepare_file(file, replace_dict)

    def handle(self):  # Override Method
        received_data = self.request.recv(2048)

        header_data = received_data[0:received_data.find(b'\r\n\r\n')]

        headers = self.parse_headers(header_data)


        buffered_data = bytearray(received_data)

        if 'Content-Length' in headers:
            data_left = int(headers['Content-Length']) - len(buffered_data)

            while data_left > 0:
                data_read_length = 2048
                if data_left < 2048:
                    data_read_length = data_left

                new_data = self.request.recv(data_read_length)
                buffered_data.extend(new_data)
                data_left = int(headers['Content-Length']) - len(buffered_data)

        client_id = self.client_address[0] + ":" + str(self.client_address[1])
        # print(received_data.decode())
        # print(client_id + " is sending data: ")

        # UNCOMMENT THIS AS SOON AS DB STUFf
        mongo_client = MongoClient("localhost:27017")
        # mongo_client = MongoClient("mongo")
        db = mongo_client["hw4_database"]

        users_collection = db["users"]
        messages_collection = db["messages"]
        class_collection = db["classes"]

        request_type = list(headers.keys())[0]
        request_path = headers[request_type].split(" ")[0]

        cookie_dict = {}
        #
        cookie_header = ""
        #
        user_info = {}

        if 'Cookie' in headers:
            print(headers['Cookie'])
            cookie_dict = self.parse_cookies(headers['Cookie'])

        if 'visits' in cookie_dict:
            user_info['visits'] = int(cookie_dict['visits']) + 1
        else:
            user_info['visits'] = 1

        # check if use logged in using auth tokens
        user_info['logged_in'] = False

        cookie_header = f"Set-Cookie: visits={user_info['visits']}; Max-Age=36000"
        #
        if 'auth_token' in cookie_dict:
            hashed_auth_token = hashlib.sha256(cookie_dict['auth_token'].encode('utf-8')).hexdigest().encode('utf-8')

            attempt_auth_data = users_collection.find_one({
                "active": 1,
                "auth_token": hashed_auth_token
            })

            if attempt_auth_data != None:
                user_info['logged_in'] = True
                user_info['username'] = attempt_auth_data['username']

        # LOAD / WEBSITE FILES
        website_files = {}

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
        for file in os.listdir("./website/image"):
            file_path = f'./website/image/{file}'
            with open(fr'{file_path}', 'rb') as read_file:
                website_files[f'image/{file}'] = read_file.read()
        for file in os.listdir("./website/user_uploads"):
            file_path = f"./website/user_uploads/{file}"
            with open(fr'{file_path}', 'rb') as read_file:
                website_files[f'user_uploads?{file}'] = read_file.read()

        # GET GET GET
        if request_type == 'GET':
            if request_path == "/":
                #  Check if user is logged in:

                if user_info['logged_in']:
                    #
                    ret_html = self.prepare_main_page(
                        website_files['main_page.html'],
                        {'logged_user': user_info['username']},
                        db,
                        user_info
                    )
                    #
                    self.request.sendall(
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(ret_html)}\r\n"
                        f"{cookie_header}\r\n"
                        f"X-Content-Type-Options: nosniff\r\n\r\n"
                        f"{ret_html}".encode()
                    )
                else:
                    #
                    ret_html = self.prepare_file(
                        website_files['login_screen.html'],
                        {'login_status': ''}
                    )
                    #
                    self.request.sendall(
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(ret_html)}\r\n"
                        f"{cookie_header}\r\n"
                        f"X-Content-Type-Options: nosniff\r\n\r\n"
                        f"{ret_html}".encode()
                    )
            elif request_path == "/create_class" or request_path == "/create_class_page.html":
                if not user_info['logged_in']:
                    #
                    ret_html = self.prepare_file(
                        website_files['login_screen.html'],
                        {'login_status': ''}
                    )
                    #
                    self.request.sendall(
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(ret_html)}\r\n"
                        f"{cookie_header}\r\n"
                        f"X-Content-Type-Options: nosniff\r\n\r\n"
                        f"{ret_html}".encode()
                    )

                ret_html = self.prepare_file(
                    website_files['create_class_page.html'],
                    {'create_class_status': ''}
                )
                #
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(ret_html)}\r\n"
                    f"{cookie_header}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{ret_html}".encode()
                )
            elif "/create_assignment" in request_path and '.css' not in request_path and '.js' not in request_path:
                if not user_info['logged_in']:
                    #
                    ret_html = self.prepare_file(
                        website_files['login_screen.html'],
                        {'login_status': ''}
                    )
                    #
                    self.request.sendall(
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(ret_html)}\r\n"
                        f"{cookie_header}\r\n"
                        f"X-Content-Type-Options: nosniff\r\n\r\n"
                        f"{ret_html}".encode()
                    )
                print('path: ' + request_path)
                class_id = int(request_path.split("/")[2])
                class_database_info = class_collection.find_one({'_id': class_id})
                if user_info['username'] != class_database_info['teacher']:
                    self.request.sendall(
                        "HTTP/1.1 403 Request Rejected\r\n"
                        "Content-Type:text/plain\r\n"
                        "Content-Length:26\r\n\r\n"
                        "The requested was rejected".encode())
                    return
                #
                ret_html = self.prepare_file(
                    website_files['create_assignment_page.html'],
                    {'class_name': class_database_info['classname'],
                     'logged_user': user_info['username']}
                )
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(ret_html)}\r\n"
                    f"{cookie_header}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{ret_html}".encode()
                )
            elif "/class/" in request_path: #/class/13
                class_id = int(request_path.split("/")[2])
                if not user_info['logged_in']:
                    #
                    ret_html = self.prepare_file(
                        website_files['login_screen.html'],
                        {'login_status': ''}
                    )
                    #
                    self.request.sendall(
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(ret_html)}\r\n"
                        f"{cookie_header}\r\n"
                        f"X-Content-Type-Options: nosniff\r\n\r\n"
                        f"{ret_html}".encode()
                    )

                class_database_info = class_collection.find_one({'_id': class_id})

                hidden_text = 'hidden'
                if class_database_info['teacher'] == user_info['username']:
                    hidden_text = ''

                ret_html = self.prepare_file(
                    website_files['class_page.html'],
                    {'class_name': class_database_info['classname'],
                     'logged_user': user_info['username'],
                     'class_id': str(class_id),
                     'is_hidden': hidden_text},
                )
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(ret_html)}\r\n"
                    f"{cookie_header}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{ret_html}".encode()
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
            elif request_path == "/class_page.css":
                # serve CSS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(website_files['class_page.css'])}\r\n"
                    f"Content-Type: text/css; charset=utf-8\r\n"
                    f"X-Content-Type-Options: nosniff"
                    f"\r\n\r\n{website_files['class_page.css']}".encode()
                )
            elif request_path == "/create_assignment_page.css":
                # serve CSS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(website_files['create_assignment_page.css'])}\r\n"
                    f"Content-Type: text/css; charset=utf-8\r\n"
                    f"X-Content-Type-Options: nosniff"
                    f"\r\n\r\n{website_files['create_assignment_page.css']}".encode()
                )
            elif request_path == "/main_page.css":
                # serve CSS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(website_files['main_page.css'])}\r\n"
                    f"Content-Type: text/css; charset=utf-8\r\n"
                    f"X-Content-Type-Options: nosniff"
                    f"\r\n\r\n{website_files['main_page.css']}".encode()
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
            elif request_path == "/class_selection.js":
                # serve JS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/javascript; charset=utf-8\r\n"
                    f"Content-Length:{len(website_files['class_selection.js'])}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{website_files['class_selection.js'].decode('utf-8')}".encode()
                )
            elif request_path == "/create_assignment.js":
                # serve JS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/javascript; charset=utf-8\r\n"
                    f"Content-Length:{len(website_files['create_assignment.js'])}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{website_files['create_assignment.js'].decode('utf-8')}".encode()
                )
            elif request_path == "/new-javascript.js":
                # serve JS
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/javascript; charset=utf-8\r\n"
                    f"Content-Length:{len(website_files['new-javascript.js'])}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{website_files['new-javascript.js'].decode('utf-8')}".encode()
                )
            elif request_path == "/AJAX_impl.js":
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/javascript; charset=utf-8\r\n"
                    f"Content-Length:{len(website_files['AJAX_impl.js'])}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{website_files['AJAX_impl.js'].decode('utf-8')}".encode()
                )
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
            elif request_path == "/websocket":
                ## WebSocket Implementation ##
                random_client_key = headers['Sec-WebSocket-Key'].strip()
                guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
                accept_key = f'{random_client_key}{guid}'
                # Compute SHA1 hash
                accept_key_hashed = hashlib.sha1(accept_key.encode()).digest()
                # Compute Base64
                accept_key_encoded = base64.b64encode(accept_key_hashed).decode()

                self.request.sendall(
                    f"HTTP/1.1 101 Upgrade\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Sec-WebSocket-Accept: {accept_key_encoded}\r\n\r\n".encode()
                )

                if 'username' not in user_info:
                    self.request.sendall(
                        "HTTP/1.1 403 Request Rejected\r\n"
                        "Content-Type:text/plain\r\n"
                        "Content-Length:26\r\n\r\n"
                        "The requested was rejected".encode())
                    return

                # Add connection to list of connections
                new_connection = {
                    'connected': True,
                    'username': user_info['username'],
                    'connection': self
                }
                #
                socket_connections[new_connection['username']] = new_connection

                # Keep connection open
                socket_open = True
                while socket_open:

                    buffered_frames = []

                    # get continuation frames (will be true if 1)
                    while True:
                        socket_data = bytearray(self.request.recv(2))   # 1
                        parsed_frame = self.parse_frame(socket_data)    # 2
                        parsed_frame['payload'] = bytearray()

                        #  Amount of data of payload read

                        payload_left = parsed_frame['payload_length']
                        while payload_left > 0:  # 4
                            read_length = 2048
                            #
                            if read_length > payload_left:
                                read_length = payload_left
                            #
                            parsed_frame['payload'].extend(self.request.recv(read_length))
                            #
                            payload_left -= read_length

                        #  All payload data has been read
                        #  Mask if necessary
                        if parsed_frame['MASK'] != 0:
                            masked_result = bytearray()
                            i = 0
                            while i < parsed_frame['payload_length']:
                                bytes_left = parsed_frame['payload_length'] - i

                                parse_bytes = 4
                                if bytes_left < 4:
                                    parse_bytes = bytes_left

                                for y in range(parse_bytes):
                                    masked_result.append(
                                        parsed_frame['payload'][i+y] ^ parsed_frame['MASK_BITS'][y]
                                    )

                                i += parse_bytes
                            #
                            parsed_frame['payload'] = masked_result

                        # payload has been masked as necessary
                        buffered_frames.append(parsed_frame)
                        if parsed_frame['FIN'] != 0:
                            break

                    #  Combine frame payloads
                    combined_payload = bytearray()
                    for frame in buffered_frames:
                        combined_payload.extend(frame['payload'])

                    #  deal with opcodes
                    #  ...
                    #  ...
                    #  Only consider opcode of first frame in buffered_frames

                    if buffered_frames[0]['opcode'] == 0b0001: #chat message
                        #
                        current_username = new_connection['username']
                        #
                        decoded_message = json.loads(combined_payload.decode('utf-8'))
                        #
                        message_type = decoded_message['messageType']
                        #
                        xsfr_data = users_collection.find_one({
                            "active": 1,
                            "username": current_username,
                            "xsfr_token": decoded_message['chatToken'],
                        })
                        #
                        print(xsfr_data)

                        if xsfr_data is None:
                            self.request.sendall(
                                "HTTP/1.1 403 Request Rejected\r\n"
                                "Content-Type:text/plain\r\n"
                                "Content-Length:26\r\n\r\n"
                                "The requested was rejected".encode())
                            return

                        if message_type == 'chatMessage':
                            self.prepare_and_send_message(
                                current_username,
                                decoded_message['comment'],
                                messages_collection
                            )
                            #
                        #
                        print(decoded_message)

                    elif buffered_frames[0]['opcode'] == 0b1000:
                        socket_connections[new_connection['username']]['connected'] = False
                        socket_open = False
            elif request_path == "/chat-history":
                all_messages = messages_collection.find({
                    "active": 1
                })

                messages_array = []

                for message in all_messages:
                    new_dict = {
                        'username': message['username'],
                        'comment': message['comment']
                    }
                    messages_array.append(new_dict)

                all_messages_decoded = json.dumps(messages_array)

                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json; charset=utf-8\r\n"
                    f"Content-Length:{len(all_messages_decoded)}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{all_messages_decoded}".encode())

                return
        elif request_type == 'POST':
            if request_path == '/user-login-register':
                content_boundary = headers['Content-Type'].split("boundary=")[1]
                # use this to get all the parts
                cb_bytes = bytearray(content_boundary, 'utf-8')
                split_sections = []
                start_index = 0
                #
                while buffered_data.find(cb_bytes, start_index + 1) != -1:
                    end_index = buffered_data.find(cb_bytes, start_index + 1)
                    split_sections.append(bytearray(buffered_data[start_index:end_index]))
                    start_index = end_index
                #
                split_sections.append(bytearray(buffered_data[start_index:]))

                form_data = {}

                for entry in split_sections:
                    # entry_headers = entry[0:entry.find(b'\r\n\r\n')].decode().split('\r\n')
                    entry_headers = self.parse_headers(entry[0:entry.find(b'\r\n\r\n')])

                    entry_content = entry[entry.find(b'\r\n\r\n') + len(b'\r\n\r\n'):]

                    if "Content-Disposition" in entry_headers and 'name="username"' in entry_headers['Content-Disposition']:
                        #
                        form_data['username'] = entry_content[0:entry_content.rfind(b'\r\n--')].decode()
                        #
                    elif "Content-Disposition" in entry_headers and 'name="password"' in entry_headers['Content-Disposition']:
                        #
                        form_data['password'] = entry_content[0:entry_content.rfind(b'\r\n--')].decode()
                        #
                    elif "Content-Disposition" in entry_headers and 'name="register_button"' in entry_headers['Content-Disposition']:
                        #
                        form_data['type'] = 'register'
                        #
                    elif "Content-Disposition" in entry_headers and 'name="login_button"' in entry_headers['Content-Disposition']:
                        #
                        form_data['type'] = 'login'
                        #

                if form_data['type'] == 'register':
                    print(
                        f"user attempting to register with credentials: [username: {form_data['username']}], [password: {form_data['password']}]")

                    # Check if user already exists
                    user_exists = users_collection.count_documents({
                        "active": 1,
                        "username": form_data['username'],
                    }) > 0

                    if user_exists:
                        print("username is already taken")
                        #
                        ret_html = self.prepare_file(
                            website_files['login_screen.html'],
                            {'login_status': 'Failed to Register: Username Taken'}
                        )
                        time.sleep(0.4)
                        self.request.sendall(
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(ret_html)}\r\n"
                            f"{cookie_header}\r\n"
                            f"X-Content-Type-Options: nosniff\r\n\r\n"
                            f"{ret_html}".encode()
                        )
                        return

                    else:
                        registration_info = {}
                        # Hash and salt password
                        password_salt = bcrypt.gensalt()
                        hashed_password = bcrypt.hashpw(form_data['password'].encode('utf-8'), password_salt)
                        #
                        registration_info['_id'] = users_collection.count_documents({}) + 1
                        registration_info['username'] = form_data['username']
                        registration_info['password'] = hashed_password
                        registration_info['salt'] = password_salt
                        registration_info['active'] = 1
                        registration_info['auth_token'] = ""
                        registration_info['xsfr_token'] = ""

                        #
                        users_collection.insert_one(registration_info)
                        #
                        print("successfully registered")
                        #
                        time.sleep(0.4)
                        ret_html = self.prepare_file(
                            website_files['login_screen.html'],
                            {'login_status': 'Successfully registered'}
                        )
                        time.sleep(0.4)
                        self.request.sendall(
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(ret_html)}\r\n"
                            f"{cookie_header}\r\n"
                            f"X-Content-Type-Options: nosniff\r\n\r\n"
                            f"{ret_html}".encode()
                        )
                        return

                elif form_data['type'] == 'login':
                    print(
                        f"user attempting to login with credentials: [username: {form_data['username']}], [password: {form_data['password']}]")
                    # check if username / password is correct

                    attempt_login_data = users_collection.find_one({
                        "active": 1,
                        "username": form_data['username']
                    })

                    if attempt_login_data is None:
                        #  failed login attempt
                        ret_html = self.prepare_file(
                            website_files['login_screen.html'],
                            {'login_status': 'Failed to Login: Incorrect Username or Password'}
                        )
                        time.sleep(0.4)
                        self.request.sendall(
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(ret_html)}\r\n"
                            f"{cookie_header}\r\n"
                            f"X-Content-Type-Options: nosniff\r\n\r\n"
                            f"{ret_html}".encode()
                        )
                        return

                    #
                    password_salt_attempt = attempt_login_data['salt']
                    hashed_password_attempt = bcrypt.hashpw(form_data['password'].encode('utf-8'), password_salt_attempt)

                    # Login failed
                    if hashed_password_attempt != attempt_login_data['password']:
                        time.sleep(0.4)
                        ret_html = self.prepare_file(
                            website_files['login_screen.html'],
                            {'login_status': 'Failed to Login: Incorrect Username or Password'}
                        )
                        self.request.sendall(
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(ret_html)}\r\n"
                            f"{cookie_header}\r\n"
                            f"X-Content-Type-Options: nosniff\r\n\r\n"
                            f"{ret_html}".encode()
                        )
                        return
                    else:
                        user_info['logged_in'] = True
                        user_info['username'] = form_data['username']

                        # create user token or whateva and do the other stuff or whateva
                        auth_token = secrets.token_hex(8)
                        hashed_auth_token = hashlib.sha256(auth_token.encode('utf-8')).hexdigest().encode('utf-8')
                        #
                        users_collection.update_one(
                            {"username": form_data['username']},
                            {"$set": {"auth_token": hashed_auth_token}}
                        )
                        #
                        auth_token_header = f"Set-Cookie: auth_token={auth_token}; Max-Age=36000; HttpOnly;"
                        time.sleep(0.4)
                        ret_html = self.prepare_main_page(
                            website_files['main_page.html'],
                            {'logged_user': user_info['username']},
                            db,
                            user_info
                        )
                        self.request.sendall(
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(ret_html)}\r\n"
                            f"{auth_token_header}\r\n"
                            f"X-Content-Type-Options: nosniff\r\n\r\n"
                            f"{ret_html}".encode()
                        )
                        return
            elif request_path == '/create-class':
                content_boundary = headers['Content-Type'].split("boundary=")[1]
                # use this to get all the parts
                cb_bytes = bytearray(content_boundary, 'utf-8')
                split_sections = []
                start_index = 0
                #
                while buffered_data.find(cb_bytes, start_index + 1) != -1:
                    end_index = buffered_data.find(cb_bytes, start_index + 1)
                    split_sections.append(bytearray(buffered_data[start_index:end_index]))
                    start_index = end_index
                #
                split_sections.append(bytearray(buffered_data[start_index:]))

                form_data = {}

                for entry in split_sections:
                    # entry_headers = entry[0:entry.find(b'\r\n\r\n')].decode().split('\r\n')
                    entry_headers = self.parse_headers(entry[0:entry.find(b'\r\n\r\n')])

                    entry_content = entry[entry.find(b'\r\n\r\n') + len(b'\r\n\r\n'):]

                    if "Content-Disposition" in entry_headers and 'name="classname"' in entry_headers['Content-Disposition']:
                        #
                        form_data['classname'] = entry_content[0:entry_content.rfind(b'\r\n--')].decode()
                        #
                    elif "Content-Disposition" in entry_headers and 'name="capacity"' in entry_headers['Content-Disposition']:
                        #
                        form_data['capacity'] = entry_content[0:entry_content.rfind(b'\r\n--')].decode()
                        #

                # TODO: Check length of class name, make sure not too short or long
                class_exists = class_collection.count_documents({
                    "active": 1,
                    "classname": form_data['classname'],
                }) > 0

                if class_exists:
                    print("class name is already taken")
                    #
                    ret_html = self.prepare_file(
                        website_files['create_class_page.html'],
                        {'create_class_status': 'Failed to Create: Class Name Taken'}
                    )
                    time.sleep(0.4)
                    self.request.sendall(
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(ret_html)}\r\n"
                        f"{cookie_header}\r\n"
                        f"X-Content-Type-Options: nosniff\r\n\r\n"
                        f"{ret_html}".encode()
                    )
                    return

                registration_info = {}
                #
                registration_info['_id'] = class_collection.count_documents({}) + 1
                registration_info['classname'] = form_data['classname']
                registration_info['capacity'] = form_data['capacity']
                registration_info['members'] = []
                registration_info['teacher'] = user_info['username']
                registration_info['active'] = 1
                #
                users_collection.update_one(
                    {"username": user_info['username']},
                    {"$push": {
                        "teaching_classes": {
                            "_id": registration_info['_id']
                        }
                    }}
                )
                #
                class_collection.insert_one(registration_info)
                #
                print("successfully created class")
                #
                time.sleep(0.4)
                ret_html = self.prepare_main_page(
                    website_files['main_page.html'],
                    {'logged_user': user_info['username']},
                    db,
                    user_info
                )
                time.sleep(0.4)
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(ret_html)}\r\n"
                    f"{cookie_header}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{ret_html}".encode()
                )
                return
            elif 'create-assignment' in request_path:
                print(request_path)

                # /class/15/create-assignment
                class_id = request_path.split("/")[2]
                print("Class ID:" + class_id)
                #
                content_boundary = headers['Content-Type'].split("boundary=")[1]
                # use this to get all the parts
                cb_bytes = bytearray(content_boundary, 'utf-8')
                split_sections = []
                start_index = 0
                #
                while buffered_data.find(cb_bytes, start_index + 1) != -1:
                    end_index = buffered_data.find(cb_bytes, start_index + 1)
                    split_sections.append(bytearray(buffered_data[start_index:end_index]))
                    start_index = end_index
                #
                split_sections.append(bytearray(buffered_data[start_index:]))

                form_data = {}

                form_data['questions'] = {}
                form_data['answers'] = {}

                # dict for question-answer pairs, form_data['questions'] = array, questions[0], etc.
                # dict for answers, form_data['answers'] = array answers[0] = array['answer 1', 'answer 2', etc.]

                print(split_sections)
                for entry in split_sections:
                    # entry_headers = entry[0:entry.find(b'\r\n\r\n')].decode().split('\r\n')
                    entry_headers = self.parse_headers(entry[0:entry.find(b'\r\n\r\n')])

                    entry_content = entry[entry.find(b'\r\n\r\n') + len(b'\r\n\r\n'):]

                    # name = "question-1"\r\n\r\n
                    if "Content-Disposition" in entry_headers and 'name="question' in entry_headers['Content-Disposition']:
                        #
                        question_sect = entry[entry.rfind(b'name='):entry.rfind(b'\r\n\r\n')]
                        question_num = question_sect.decode().split("-")[1].replace('"', "")
                        #
                        form_data['questions'][int(question_num)] = entry_content[0:entry_content.rfind(b'\r\n--')].decode()
                        #
                    elif "Content-Disposition" in entry_headers and 'name="answer' in entry_headers['Content-Disposition']:
                        #
                        answer_sect = entry[entry.rfind(b'name='):entry.rfind(b'\r\n\r\n')]
                        question_num = answer_sect.decode()[answer_sect.rfind(b'-')+1:answer_sect.rfind(b'-')+2]
                        answer_num = answer_sect.decode()[answer_sect.rfind(b'_')+1:answer_sect.rfind(b'_')+2]
                        #
                        if int(question_num) not in form_data['answers']:
                            form_data['answers'][int(question_num)] = {int(answer_num): entry_content[
                                                                      0:entry_content.rfind(b'\r\n--')].decode()}
                        else:
                            form_data['answers'][int(question_num)][int(answer_num)] = entry_content[0:entry_content.rfind(b'\r\n--')].decode()
                        #

                # TODO: MAKE SURE NO QUESTIONS OR ANSWERS ARE BLANK

                print(form_data)

                new_assignment = {}
                new_assignment['questions'] = {str(k): v for k, v in form_data['questions'].items()}
                new_assignment['answers'] = {str(k): {str(k2): v2 for k2, v2 in v.items()} for k, v in
                                             form_data['answers'].items()}

                class_collection.update_one(
                    {"_id": int(class_id)},
                    {"$push": {
                        "assignments": new_assignment
                    }}
                )
                time.sleep(0.1)

                class_database_info = class_collection.find_one({'_id': int(class_id)})
                #
                print("successfully created assignment")
                #
                time.sleep(0.4)
                ret_html = self.prepare_file(
                    website_files['class_page.html'],
                    {'class_name': class_database_info['classname'],
                     'logged_user': user_info['username'],
                     'class_id': str(class_id),
                     'is_hidden': ''},
                )
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(ret_html)}\r\n"
                    f"{cookie_header}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{ret_html}".encode()
                )
                return
            elif request_path == '/join-class':
                content_length = int(headers['Content-Length'])
                post_data = buffered_data[buffered_data.find(b'\r\n\r\n') + len(b'\r\n\r\n'):].decode('utf-8')
                class_data = json.loads(post_data)
                class_id = int(class_data['class_id'])

                class_database_info = class_collection.find_one({"_id": class_id})

                if user_info['username'] in class_database_info['members']:
                    print('User already enrolled')
                    self.request.sendall(
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Content-Type:text/plain\r\n"
                        "Content-Length:20\r\n\r\n"
                        "Failed to join class".encode())
                    return

                if user_info['username'] == class_database_info['teacher']:
                    print("can't join class that you're teaching")
                    self.request.sendall(
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Content-Type:text/plain\r\n"
                        "Content-Length:20\r\n\r\n"
                        "Failed to join class".encode())
                    return

                if len(class_database_info['members']) >= int(class_database_info['capacity']):
                    print("class is already filled")
                    self.request.sendall(
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Content-Type:text/plain\r\n"
                        "Content-Length:20\r\n\r\n"
                        "Failed to join class".encode())
                    return

                # Successfully can join
                users_collection.update_one(
                    {"username": user_info['username']},
                    {"$push": {
                        "joined_classes": {
                            "_id": class_id
                        }
                    }}
                )
                class_collection.update_one(
                    {"_id": class_id},
                    {"$push": {
                        "members": {
                            "username": user_info['username']
                        }
                    }}
                )
                #
                time.sleep(0.4)
                #
                ret_html = self.prepare_main_page(
                    website_files['main_page.html'],
                    {'logged_user': user_info['username']},
                    db,
                    user_info
                )
                #
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(ret_html)}\r\n"
                    f"{cookie_header}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n\r\n"
                    f"{ret_html}".encode()
                )
                return
                # 4. Display notifcations for successes or failures
        return

socket_connections = {}

if __name__ == "__main__":
    host = '0.0.0'
    port = 8080
    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)
    server.serve_forever()
