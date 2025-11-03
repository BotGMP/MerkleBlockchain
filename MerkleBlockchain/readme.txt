Para correr (pode alterar os argumentos): 
mvn -q clean compile
mvn --% -q exec:java -Dexec.args="SHA-256 10 0 20000"