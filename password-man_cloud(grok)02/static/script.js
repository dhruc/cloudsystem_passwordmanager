function generatePassword() {
    fetch('/generate_password')
        .then(response => response.json())
        .then(data => {
            document.getElementById('password').value = data.password;
        });
}

function showPassword(id) {
    fetch(`/get_password/${id}`)
        .then(response => response.json())
        .then(data => {
            if (data.password) {
                navigator.clipboard.writeText(data.password);
                alert(`Password copied to clipboard: ${data.password}`);
            } else {
                alert('Error retrieving password');
            }
        });
}

function fetchExport() {
    fetch('/export')
        .then(response => response.json())
        .then(data => {
            document.getElementById('exportData').value = data.encrypted_vault;
        });
}

function filterEntries() {
    let input = document.getElementById('search').value.toLowerCase();
    let table = document.getElementById('entryTable');
    let tr = table.getElementsByTagName('tr');
    for (let i = 1; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName('td');
        if (td[0].textContent.toLowerCase().indexOf(input) > -1 || td[1].textContent.toLowerCase().indexOf(input) > -1) {
            tr[i].style.display = "";
        } else {
            tr[i].style.display = "none";
        }
    }
}