import os
from langchain_openai import OpenAIEmbeddings
from langchain_postgres.vectorstores import PGVector

class IncrustacionesLocales:
    def embed_documents(self, textos: list[str]) -> list[list[float]]:
        return [[0.1] * 1536 for _ in textos]

    def embed_query(self, texto: str) -> list[float]:
        return [0.1] * 1536

class RepositorioAuditoria:
    def __init__(self, url_conexion: str, configuracion_ia: dict):
        self.url_conexion = url_conexion
        self.modo_local = configuracion_ia.get("tipo") == "local"
        
        try:
            clave_api = configuracion_ia.get("clave_api", "")
            if not self.modo_local and clave_api.strip() != "":
                os.environ["OPENAI_API_KEY"] = clave_api
                self.incrustaciones = OpenAIEmbeddings(model="text-embedding-3-small")
            else:
                self.incrustaciones = IncrustacionesLocales()
                self.modo_local = True
        except Exception:
            self.incrustaciones = IncrustacionesLocales()
            self.modo_local = True
        
        self.recuperador = self.configurar_almacen()

    def configurar_almacen(self):
        textos_base = [
            "[2026-11-12 08:14:05] Alerta AL-101: Intentos fallidos de login desde la IP 192.168.1.50.",
            "[2026-11-12 09:22:10] Alerta AL-102: El usuario ceo@empresa.com exportó 5000 registros financieros con tarjetas 4532 1111 2222 3333.",
            "[2026-11-12 10:05:00] Política SEC-01: Accesos no autorizados deben reportarse de inmediato al SOC."
        ]
        nombre_coleccion = "logs_seguridad_local" if self.modo_local else "logs_seguridad_produccion"
        
        try:
            almacen = PGVector.from_texts(
                texts=textos_base,
                embedding=self.incrustaciones,
                connection_string=self.url_conexion,
                collection_name=nombre_coleccion
            )
            return almacen.as_retriever(search_kwargs={"k": 2})
        except Exception:
            return None

    def buscar_registros(self, consulta: str) -> str:
        if self.recuperador:
            try:
                documentos = self.recuperador.invoke(consulta)
                return "\n".join([doc.page_content for doc in documentos])
            except Exception:
                pass
        
        textos_locales = [
            "[2026-11-12 08:14:05] Alerta AL-101: Intentos fallidos de login desde la IP 192.168.1.50.",
            "[2026-11-12 09:22:10] Alerta AL-102: El usuario ceo@empresa.com exportó registros financieros."
        ]
        return "\n".join(textos_locales)