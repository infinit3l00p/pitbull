"""BrainMaze — Cognitive Confusion Engine for PITBULL.

Extends the Labyrinth deception system with advanced confusion techniques:
- LLM-powered fake personas that interact with attackers
- False trail generators (DNS, credentials, history, configs, users)
- Paranoia inducer that makes attackers think someone else is in the system
- Time wasters that generate decoy content to burn attacker time
- Orchestrator that coordinates all techniques based on attacker behavior
"""

from app.brainmaze.persona import PersonaEngine, Persona
from app.brainmaze.false_trails import FalseTrailGenerator
from app.brainmaze.paranoia import ParanoiaInducer
from app.brainmaze.time_wasters import TimeWasterGenerator
from app.brainmaze.orchestrator import BrainMazeOrchestrator, get_brainmaze_orchestrator

__all__ = [
    "PersonaEngine",
    "Persona",
    "FalseTrailGenerator",
    "ParanoiaInducer",
    "TimeWasterGenerator",
    "BrainMazeOrchestrator",
    "get_brainmaze_orchestrator",
]
from app.core.database import cypher_write

def init_neo4j_schema() -> None:
    """Initialize Neo4j schema for BrainMaze."""
    cypher_write("CREATE CONSTRAINT false_trail_id IF NOT EXISTS FOR (f:FalseTrail) REQUIRE f.trail_id IS UNIQUE")
    cypher_write("CREATE CONSTRAINT persona_interaction_id IF NOT EXISTS FOR (p:PersonaInteraction) REQUIRE p.interaction_id IS UNIQUE")
