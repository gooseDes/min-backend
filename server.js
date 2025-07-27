const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors')
require('dotenv').config()

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*"
    }
});

app.use(cors())
app.use(express.json())

io.on('connection', (socket) => {
    console.log(`User ${socket.id} connected!`)

    socket.on('message', (data) => {
        io.emit('message', data);
    });

    socket.on('disconnect', () => {
        console.log(`User ${socket.id} disconnected!`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on ${PORT} port!`);
});