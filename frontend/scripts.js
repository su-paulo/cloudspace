document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('addUserForm')) {
        document.getElementById('addUserForm').addEventListener('submit', addUser);
    }

    if (document.getElementById('deleteUserForm')) {
        document.getElementById('deleteUserForm').addEventListener('submit', deleteUser);
    }

    if (document.getElementById('contactsTable')) {
        fetchContacts();
    }
    if (document.getElementById('loginButton')) {
        document.getElementById('loginButton').addEventListener('click', openLoginPopup);
    }
});

function openLoginPopup() {
    const popup = document.createElement('div');
    popup.id = 'loginPopup';
    popup.innerHTML = `
        <div class="popup-content">
            <span class="close-button" onclick="closeLoginPopup()">&times;</span>
            <h2>Login</h2>
            <input type="text" id="popupUsername" placeholder="Username">
            <input type="password" id="popupPassword" placeholder="Password">
            <button onclick="handleLogin()">Login</button>
        </div>
    `;
    document.body.appendChild(popup);
}

function closeLoginPopup() {
    const popup = document.getElementById('loginPopup');
    if (popup) {
        document.body.removeChild(popup);
    }
}

function handleLogin() {
    const username = document.getElementById('popupUsername').value;
    const password = document.getElementById('popupPassword').value;
    login(username, password);
}

function login(username, password) {
    fetch('http://localhost:8000/admin/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'username': username,
            'password': password,
        }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Login failed');
        }
        return response.json();
    })
    .then(data => {
        localStorage.setItem('token', data.access_token);
        alert('Login successful');
        closeLoginPopup();
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to login');
    });
}

function fetchContacts() {
    const token = localStorage.getItem('token');
    fetch('http://localhost:8000/api/v1/users/', {
        method: 'GET',
/*         headers: {
            'Authorization': `Bearer ${token}`,
        }, */
    })
    .then(response => response.json())
    .then(data => {
        const tableBody = document.querySelector('#contactsTable tbody');
        tableBody.innerHTML = ''; // Clear existing rows
        data.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user.userid}</td>
                <td>${user.name}</td>
                <td>${user.alias}</td>
                <td>${user.email}</td>
                <td>${user.role}</td>
            `;
            tableBody.appendChild(row);
        });
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to fetch users');
    });
}

function addUser(event) {
    event.preventDefault();
    const token = localStorage.getItem('token');
    const formData = new FormData(event.target);
    const user = {
        userid: formData.get('userid'),
        name: formData.get('name'),
        alias: formData.get('alias'),
        email: formData.get('email'),
        role: formData.get('role')
    };

    fetch('http://localhost:8000/api/v1/users/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(user)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to add user');
        }
        return response.json();
    })
    .then(data => {
        alert('User added successfully');
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to add user');
    });
}

function deleteUser(event) {
    const token = localStorage.getItem('token');    
    event.preventDefault();
    const userId = document.getElementById('deleteUserId').value;

    fetch(`http://localhost:8000/api/v1/users/${userId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`,           
        },        
    })
    .then(response => {
        if (response.ok) {
            alert('User deleted successfully');
            event.target.reset();
        } else {
            alert('Failed to delete user');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to delete user');
    });
}


function fetchHeaders() {
    fetch('http://localhost:8000/api/v1/users/', {
        method: 'GET',
    })
    .then(response => {
        document.getElementById('requestHeaders').textContent = JSON.stringify([...response.headers], null, 2);
        return response.json();
    })
    .then(data => {
        document.getElementById('responseHeaders').textContent = JSON.stringify(data, null, 2);
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to fetch headers');
    });
}