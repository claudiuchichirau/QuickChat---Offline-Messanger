# QuickChat
QuickChat is a client-server application that enables communication between two users. Each user is identified by a unique ID, and messages exchanged between them are in the form of text, including the ability to send emojis and images.

**The presentation video of the project**: https://www.youtube.com/watch?v=igPTQ-ZWcQI

## Technologies Used
- Programming Language: The application is developed in Python.
- Database: PostgreSQL is utilized for data storage, with three main tables:
  - **users**: Stores usernames and encrypted passwords of users, using a salt generated at account creation.
  - **salt_storage**: Contains information about the salts associated with each user for password encryption.
  - **encryption_keys**: Holds encryption/decryption keys for conversations between two users.
- Password Encryption: Upon account creation, the user's password is encrypted using a specific salt for each account, ensuring enhanced security.

## Conversation Structure
1. Conversations between two users are stored locally as **encrypted** log files in XML format.
2. Each XML file contains information such as the date, sender, time of sending, and the content of the message.

## Key Features
1. Encrypted Communication: All messages are encrypted to ensure communication confidentiality.
2. Emojis and Images: Users can send emojis and images within their conversations.
3. Message History: Users have the ability to track the history of received and sent messages.
4. Unique ID Management: User IDs are managed to ensure uniqueness for each client.

## Statement of the problem: 
"To write a graphical client-server application through which 2 clients can communicate with each other. Each client will have an assigned id. The messages will be sent to a specific id and will be in the form of text messages. will be saved in a file and it will be possible to track the history of messages received/sent to a certain client. Client IDs must be unique. Communication must be encrypted, and allow emojy as well as sending pictures."
