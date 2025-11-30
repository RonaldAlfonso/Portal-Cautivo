

class Html:
    html_login = """
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="UTF-8">
        <title>Portal Cautivo</title>

        <style>
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: #f0f0f0;
                font-family: Arial, sans-serif;
            }

            #login-container {
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0px 0px 12px rgba(0,0,0,0.2);
                width: 330px;
                text-align: center;
            }

            h1 {
                margin-top: 0;
                margin-bottom: 20px;
                font-size: 24px;
            }

            label {
                display: block;
                text-align: left;
                margin-bottom: 5px;
                font-weight: bold;
            }

            input {
                width: 100%;
                padding: 10px;
                margin-bottom: 20px;
                border-radius: 6px;
                border: 1px solid #ccc;
            }

            button {
                width: 100%;
                padding: 10px;
                background: #0078ff;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
            }

            button:hover {
                background: #005fcc;
            }
        </style>

        </head>
        <body>

        <div id="login-container">
            <h1>Portal Cautivo</h1>

            <form id="loginForm">
                <label>Usuario:</label>
                <input type="text" id="user" name="user">

                <label>Contraseña:</label>
                <input type="password" id="pass" name="pass">

                <button type="submit">Entrar</button>
            </form>
        </div>

        <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const user = document.getElementById('user').value;
            const pass = document.getElementById('pass').value;

            const body = `user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`;

            const response = await fetch('/', {
                method: 'POST',
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: body
            });

            const text = await response.text();
            document.body.innerHTML = text;
        });
        </script>

        </body>
        </html>


        """

    html_ok = """
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>OK</title></head>
        <body>
        <h1>Acceso concedido</h1>
        <p>Ya puedes navegar.</p>
        </body>
        </html>
        """
    def __init__(self):
        pass