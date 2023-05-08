const socket = new WebSocket('ws://' + window.location.host + '/websocket');
const classId = window.location.pathname.split('/')[2];

function closeAssignment(class_id, assignment_id) {
    //
    const data = {
        class_id: class_id,
        assignment_id: assignment_id
    };
    //
    fetch('/close-assignment', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data),
    })
    .then(response => {
        if (!response.ok) {
            console.log('error');
        }
    })
    .then(data => {
        console.log(data);
//        console.log("sending refresh request")
//        sendRefreshRequest(class_id);
    })
    .catch(error => {
        console.error(error);
    });
}

// Called whenever data is received from the server over the WebSocket connection
socket.onmessage = function (ws_message) {
    const message = JSON.parse(ws_message.data);
    const messageType = message.messageType

    console.log("recieved request here")
    console.log(message)
    console.log("<")

    if(message.class_id == classId) {
        switch (messageType) {
            case 'refreshRequest':
                location.reload();
                break;
            default:
                console.log("received an invalid WS messageType");
        }
    }
}