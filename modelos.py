from pydantic import BaseModel
from typing import TypedDict

class EventoSeguridad(BaseModel):
    nivel: str
    mensaje: str
    entidades_ofuscadas: int

class SolicitudAnalisis(BaseModel):
    consulta: str
    identificador_sesion: str

class RespuestaAnalisis(BaseModel):
    respuesta_modelo: str
    estado_seguridad: str
    eventos: list[EventoSeguridad]

class EstadoGrafo(TypedDict):
    consulta_original: str
    consulta_saneada: str
    contexto_recuperado: str
    respuesta_generada: str
    intentos_intrusion: int
    eventos_auditoria: list[dict]