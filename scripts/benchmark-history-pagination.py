"""Measure command-history candidate indexes in a uniquely named loopback DB.

Requires psycopg in test tooling, not an application dependency. Never connects
to or modifies a deployment database. Records plans, not an HTTP benchmark.
"""
import json
from pathlib import Path
import uuid
import sys
import psycopg
from psycopg import sql

root = Path(__file__).resolve().parents[1]
security = '--security' in sys.argv
name = 'mitras_history_bench_' + uuid.uuid4().hex
options = dict(host='127.0.0.1', port=55518, user='codex_test', connect_timeout=5)
with psycopg.connect(dbname='postgres', autocommit=True, **options) as admin:
    admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    try:
        with psycopg.connect(dbname=name, autocommit=True, **options) as db:
            if security:
                db.execute((root/'connection-manager/internal/database/migrations/052_security_events.up.sql').read_text(encoding='utf-8'))
                db.execute("""INSERT INTO security_events(id,event_type,severity,actor_id,description,metadata,created_at)
                    SELECT md5(n::text)::uuid,'login_failed','warning',md5((n%1000)::text)::uuid,repeat('details',150),jsonb_build_object('evidence',repeat('full',300)),
                    now()-interval '1 hour'+(n%10000)*interval '1 microsecond' FROM generate_series(1,125000) n""")
                db.execute('ANALYZE security_events')
                base="SELECT id,event_type,severity,actor_id,actor_name,target_id,target_type,ip_address,''::text,left(description,256),'{}'::jsonb,created_at FROM security_events WHERE created_at>=now()-interval '1 day' AND created_at<=now()"
                queries={'global':base+' ORDER BY created_at DESC,id DESC LIMIT 26', 'actor':base+" AND actor_id=md5('42')::uuid ORDER BY created_at DESC,id DESC LIMIT 26"}
                indexes=['CREATE INDEX CONCURRENTLY idx_security_events_page_created_id ON security_events(created_at DESC,id DESC)','CREATE INDEX CONCURRENTLY idx_security_events_page_actor_created_id ON security_events(actor_id,created_at DESC,id DESC)']
                table='security_events'
            else:
                db.execute('CREATE TABLE agents(id uuid PRIMARY KEY,hostname text); CREATE TABLE users(id uuid PRIMARY KEY,username text)')
                db.execute((root/'connection-manager/internal/database/migrations/009_create_commands.up.sql').read_text(encoding='utf-8'))
                db.execute("INSERT INTO agents SELECT md5(n::text)::uuid,'host-'||n FROM generate_series(0,999) n")
                db.execute("""INSERT INTO commands(id,agent_id,command_type,parameters,status,issued_at)
                    SELECT md5(n::text)::uuid,md5((n%1000)::text)::uuid,'collect_logs',jsonb_build_object('payload',repeat('payload',150)),
                    'completed',now()-interval '1 hour'+(n%10000)*interval '1 microsecond' FROM generate_series(1,125000) n""")
                db.execute('ANALYZE commands; ANALYZE agents; ANALYZE users')
                base = """SELECT c.id,c.agent_id,COALESCE(a.hostname,''),c.command_type,
                    jsonb_strip_nulls(jsonb_build_object('decision_reason',left(c.parameters->>'decision_reason',256),'decision_confidence',left(c.parameters->>'decision_confidence',64),'d3fend_mapping',left(c.parameters->>'d3fend_mapping',128))),c.priority,c.status,NULL::jsonb,left(COALESCE(c.error_message,''),256),c.exit_code,
                    c.timeout_seconds,c.issued_at,c.sent_at,c.completed_at,c.expires_at,c.issued_by,
                    COALESCE(u.username,c.metadata->>'issued_by_username','')
                    FROM commands c LEFT JOIN agents a ON a.id=c.agent_id LEFT JOIN users u ON u.id=c.issued_by
                    WHERE c.issued_at>=now()-interval '1 day' AND c.issued_at<=now()"""
                queries = {'global':base+' ORDER BY c.issued_at DESC,c.id DESC LIMIT 26',
                           'agent':base+" AND c.agent_id=md5('42')::uuid ORDER BY c.issued_at DESC,c.id DESC LIMIT 26"}
                indexes=['CREATE INDEX CONCURRENTLY idx_commands_page_issued_id ON commands(issued_at DESC,id DESC)','CREATE INDEX CONCURRENTLY idx_commands_page_agent_issued_id ON commands(agent_id,issued_at DESC,id DESC)']
                table='commands'
            result = {'rows':125000,'scope':table+' list projection, synthetic data; SQL plans only','before':{},'after':{}}
            for stage in ('before','after'):
                if stage=='after':
                    for ddl in indexes: db.execute(ddl)
                    db.execute(sql.SQL('ANALYZE {}').format(sql.Identifier(table)))
                for label,query in queries.items():
                    plans=[db.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+query).fetchone()[0][0] for _ in range(3)]
                    result[stage][label]={'execution_ms':[p['Execution Time'] for p in plans],'plans':plans}
            (root/'docs/pagination'/('security-plans.json' if security else 'command-plans.json')).write_text(json.dumps(result,indent=2),encoding='utf-8')
            print(json.dumps({stage:{key:val['execution_ms'] for key,val in result[stage].items()} for stage in ('before','after')}))
    finally:
        admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
