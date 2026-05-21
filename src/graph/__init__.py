from neo4j import GraphDatabase
from pyshare.src.core.config import settings

class Neo4jDriverProvider:
    
    def __init__(self):
        
        self._uri = settings.neo4j_uri
        self._user = settings.neo4j_user
        self._password = settings.neo4j_password
        self._driver = None

    def connect(self):
        if not self._driver:
            self._driver = GraphDatabase.driver(
                self._uri, 
                auth=(self._user, self._password)
            )
        return self._driver

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    def get_session(self):
        """Trả về một session sạch để thực thi các câu lệnh Cypher"""
        driver = self.connect()
        return driver.session()


db_provider = Neo4jDriverProvider()
