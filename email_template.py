def generar_html_recuperacion(usuario: str, token: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recuperación de Contraseña</title>
</head>
<body style="font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px 0; color: #333333;">
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; background-color: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #e1e8ed; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
        <!-- ENCABEZADO -->
        <tr>
            <td style="background-color: #1a365d; padding: 28px 24px; text-align: center;">
                <h1 style="color: #ffffff; font-size: 22px; margin: 0; font-weight: 700; letter-spacing: 0.5px;">Sistema de Autenticación</h1>
            </td>
        </tr>
        
        <!-- CUERPO DEL MENSAJE -->
        <tr>
            <td style="padding: 32px 28px;">
                <div style="font-size: 16px; font-weight: 600; color: #2d3748; margin-bottom: 12px;">¡Hola, {usuario}! 👋</div>
                <p style="font-size: 14px; line-height: 1.6; color: #4a5568; margin-top: 0; margin-bottom: 20px;">
                    Hemos recibido una solicitud para restablecer la contraseña de tu cuenta. Copia el siguiente token para realizar el cambio en la plataforma:
                </p>
                
                <!-- CAJA DEL TOKEN -->
                <div style="background-color: #edf2f7; border-left: 4px solid #3182ce; border-radius: 6px; padding: 16px; margin: 24px 0; word-break: break-all; font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #2d3748;">
                    <div style="font-family: 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #718096; font-weight: bold; margin-bottom: 8px;">Token de recuperación</div>
                    {token}
                </div>

                <p style="font-size: 13px; color: #e53e3e; margin-top: 16px; margin-bottom: 20px; font-weight: 500;">
                    ⚠️ Por razones de seguridad, este token caducará automáticamente en <strong>15 minutos</strong>.
                </p>
                
                <p style="font-size: 13px; color: #718096; margin: 0; font-style: italic;">
                    Si no solicitaste este cambio de contraseña, puedes ignorar este correo de manera segura. Tu contraseña actual no cambiará.
                </p>
            </td>
        </tr>
        
        <!-- PIE DE PÁGINA -->
        <tr>
            <td style="background-color: #f8fafc; padding: 20px 28px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #a0aec0; text-align: center; line-height: 1.5;">
                Este es un correo automático, por favor no respondas a este mensaje.<br>
                © 2026 Sistema de Autenticación FastAPI. Todos los derechos reservados.
            </td>
        </tr>
    </table>
</body>
</html>"""
