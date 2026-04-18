from langchain_core.prompts import ChatPromptTemplate
from . import messages


agent_prompt = ChatPromptTemplate.from_messages([
    ("system", messages.agent_system_message),
    ("human", messages.agent_human_message),
])
