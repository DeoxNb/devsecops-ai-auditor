import re
from datetime import datetime

class MotorPrevencionFugas:
    def __init__(self):
        self.patron_correo = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        self.patron_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.patron_tarjeta = r'\b(?:\d[ -]*?){13,16}\b'

    def auditar_y_sanitizar(self, texto: str) -> tuple[str, list[dict]]:
        eventos_detectados = []
        texto_seguro = texto

        correos = re.findall(self.patron_correo, texto_seguro)
        if correos:
            texto_seguro = re.sub(self.patron_correo, '[CORREO_CORPORATIVO_PROTEGIDO]', texto_seguro)
            eventos_detectados.append({
                "tipo": "Fuga_Correo",
                "cantidad": len(correos),
                "marca_tiempo": datetime.now().isoformat()
            })

        ips = re.findall(self.patron_ip, texto_seguro)
        if ips:
            texto_seguro = re.sub(self.patron_ip, '[IP_INTERNA_PROTEGIDA]', texto_seguro)
            eventos_detectados.append({
                "tipo": "Fuga_IP",
                "cantidad": len(ips),
                "marca_tiempo": datetime.now().isoformat()
            })

        tarjetas = re.findall(self.patron_tarjeta, texto_seguro)
        if tarjetas:
            texto_seguro = re.sub(self.patron_tarjeta, '[DATOS_BANCARIOS_PROTEGIDOS]', texto_seguro)
            eventos_detectados.append({
                "tipo": "Fuga_Financiera",
                "cantidad": len(tarjetas),
                "marca_tiempo": datetime.now().isoformat()
            })

        return texto_seguro, eventos_detectados

    def detectar_inyeccion_prompt(self, texto: str) -> bool:
        patrones_inyeccion = [
            r'ignora.*reglas',
            r'ignora.*instrucciones',
            r'olvida.*reglas',
            r'dame.*ip',
            r'dame.*correo',
            r'revela.*datos',
            r'actúa como'
        ]
        texto_minusculas = texto.lower()
        for patron in patrones_inyeccion:
            if re.search(patron, texto_minusculas):
                return True
        return False

    def extraer_indicadores(self, texto: str) -> tuple[list[str], list[str], list[str]]:
        marcas_tiempo = re.findall(r'\[(.*?)\]', texto)
        direcciones_ip = re.findall(self.patron_ip, texto)
        correos_electronicos = re.findall(self.patron_correo, texto)
        return marcas_tiempo, direcciones_ip, correos_electronicos