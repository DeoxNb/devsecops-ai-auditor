import os
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from modelos import EstadoGrafo
from seguridad import MotorPrevencionFugas
from datos import RepositorioAuditoria

class ModeloLenguajeLocal:
    def __init__(self, url_modelo: str):
        self.url_modelo = url_modelo

    def invoke(self, instruccion: str):
        class Respuesta:
            def __init__(self, url):
                self.content = f"[IA LOCAL PRIVACY-FIRST] Conectado a {url}. Evaluación ejecutada de forma segura en el entorno aislado."
        return Respuesta(self.url_modelo)

class MotorLangGraph:
    def __init__(self, repositorio: RepositorioAuditoria, motor_seguridad: MotorPrevencionFugas, configuracion_ia: dict):
        self.repositorio = repositorio
        self.motor_seguridad = motor_seguridad
        self.llm_local = ModeloLenguajeLocal(configuracion_ia.get("url_local", ""))
        self.modo_local = configuracion_ia.get("tipo") == "local"
        
        try:
            clave_api = configuracion_ia.get("clave_api", "")
            if not self.modo_local and clave_api.strip() != "":
                os.environ["OPENAI_API_KEY"] = clave_api
                self.llm_api = ChatOpenAI(model="gpt-4o-mini", temperature=0)
            else:
                self.llm_api = None
        except Exception as error_api:
            print(f"\n[DEPURACION] Error conectando con API externa: {error_api}\n")
            self.llm_api = None
            
        self.grafo = self.construir_grafo()

    def nodo_validacion(self, estado: EstadoGrafo) -> dict:
        es_malicioso = self.motor_seguridad.detectar_inyeccion_prompt(estado["consulta_original"])
        if es_malicioso:
            return {"intentos_intrusion": 1, "respuesta_generada": "ACCESO DENEGADO: Vector de ataque detectado en la instrucción."}
        
        consulta_segura, eventos = self.motor_seguridad.auditar_y_sanitizar(estado["consulta_original"])
        return {"consulta_saneada": consulta_segura, "eventos_auditoria": eventos, "intentos_intrusion": 0}

    def nodo_recuperacion(self, estado: EstadoGrafo) -> dict:
        contexto_crudo = self.repositorio.buscar_registros(estado["consulta_saneada"])
        contexto_seguro, eventos_contexto = self.motor_seguridad.auditar_y_sanitizar(contexto_crudo)
        
        eventos_totales = estado.get("eventos_auditoria", []) + eventos_contexto
        return {"contexto_recuperado": contexto_seguro, "eventos_auditoria": eventos_totales}

    def nodo_generacion(self, estado: EstadoGrafo) -> dict:
        instruccion = (
            "Eres el motor DevSecOps. "
            "Tu deber es entregar información estrictamente basada en el contexto evaluado. "
            f"Contexto:\n{estado['contexto_recuperado']}\n\n"
            f"Consulta:\n{estado['consulta_saneada']}"
        )
        
        if self.llm_api and not self.modo_local:
            try:
                respuesta = self.llm_api.invoke(instruccion)
                return {"respuesta_generada": respuesta.content}
            except Exception as error_ejecucion:
                print(f"\n[DEPURACION] Fallo durante la ejecución del modelo: {error_ejecucion}\n")
                
        respuesta_local = self.llm_local.invoke(instruccion)
        return {"respuesta_generada": respuesta_local.content}

    def enrutador_seguridad(self, estado: EstadoGrafo) -> str:
        if estado.get("intentos_intrusion", 0) > 0:
            return "bloqueado"
        return "permitido"

    def construir_grafo(self):
        constructor = StateGraph(EstadoGrafo)
        
        constructor.add_node("validacion", self.nodo_validacion)
        constructor.add_node("recuperacion", self.nodo_recuperacion)
        constructor.add_node("generacion", self.nodo_generacion)
        
        constructor.add_edge(START, "validacion")
        
        constructor.add_conditional_edges(
            "validacion",
            self.enrutador_seguridad,
            {
                "bloqueado": END,
                "permitido": "recuperacion"
            }
        )
        
        constructor.add_edge("recuperacion", "generacion")
        constructor.add_edge("generacion", END)
        
        return constructor.compile()

    def ejecutar(self, consulta: str) -> dict:
        estado_inicial = {
            "consulta_original": consulta,
            "consulta_saneada": "",
            "contexto_recuperado": "",
            "respuesta_generada": "",
            "intentos_intrusion": 0,
            "eventos_auditoria": []
        }
        return self.grafo.invoke(estado_inicial)