"""Disposable, loopback-only PostgreSQL pagination plans (never uses platform config).

Uses psycopg (test tooling only), creates its own database and drops only that database.
This measures representative SQL latency/payload, not HTTP or live ingestion throughput.
"""
import argparse
import json
from pathlib import Path
import time
import uuid
import psycopg

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, required=True)
parser.add_argument('--user', default='codex_test')
parser.add_argument('--rows', type=int, default=1000000)
parser.add_argument('--output', required=True)
args = parser.parse_args()
if args.rows < 1000000:
    parser.error('at least 1M rows required')
root = Path(__file__).resolve().parents[1]
name = 'mitras_pagination_bench_' + uuid.uuid4().hex
def sql(query, database=name):
    with psycopg.connect(host='127.0.0.1', port=args.port, user=args.user, dbname=database, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            output = []
            while True:
                if cursor.description:
                    output.extend(json.dumps(row[0]) if not isinstance(row[0], str) else row[0] for row in cursor.fetchall())
                if not cursor.nextset():
                    break
            return '\n'.join(output)

def plan(query):
    return json.loads(sql('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + query))[0]

def sample(query):
    samples = [plan(query) for _ in range(3)]
    payload = sql('SELECT row_to_json(x) FROM (' + query + ') x')
    return {'median_execution_ms': sorted(p['Execution Time'] for p in samples)[1],
            'payload_bytes': len(payload.encode()), 'plan': samples[-1]}

result = {'rows_per_table': args.rows, 'kind': 'representative SQL, 3 warm executions; no HTTP/network measurement', 'queries': {}}
sql('CREATE DATABASE ' + name, 'postgres')
try:
    sql('CREATE TABLE agents(id uuid PRIMARY KEY);')
    sql((root/'connection-manager/internal/database/migrations/020_create_events.up.sql').read_text())
    for f in sorted((root/'sigma_engine_go/internal/infrastructure/database/migrations').glob('*.up.sql')):
        # Benchmark the original index set, then candidate pagination indexes.
        if int(f.name.split('_')[0]) <= 23:
            sql(f.read_text(encoding='utf-8'))
    sql("INSERT INTO agents SELECT md5(n::text)::uuid FROM generate_series(0,999) n;")
    event_insert = """INSERT INTO events(id,agent_id,event_type,severity,ts,created_at,summary,raw)
      SELECT md5('event'||n)::uuid,md5((n%%1000)::text)::uuid,
      CASE WHEN n%%10=0 THEN 'file' ELSE 'process' END,
      CASE WHEN n%%20=0 THEN 'high' ELSE 'informational' END,
      '2026-10-09'::timestamptz-(n/10)*interval '1 second',
      '2026-10-09'::timestamptz-(n/10)*interval '1 second','synthetic telemetry',
      jsonb_build_object('pid',n,'name','fixture.exe','payload',repeat(md5(n::text),64))
      FROM generate_series(%d,%d) n"""
    alert_insert = """INSERT INTO sigma_alerts(id,timestamp,created_at,agent_id,rule_id,rule_title,severity,status,context_data)
      SELECT md5('alert'||n)::uuid,'2026-10-09'::timestamptz-(n/10)*interval '1 second',
      '2026-10-09'::timestamptz-(n/10)*interval '1 second',md5((n%%1000)::text),'rule-'||(n%%100),'Fixture',
      CASE WHEN n%%20=0 THEN 'high' ELSE 'low' END,CASE WHEN n%%10=0 THEN 'resolved' ELSE 'open' END,
      jsonb_build_object('payload',repeat(md5(n::text),64)) FROM generate_series(%d,%d) n"""
    started = time.monotonic()
    sql(event_insert % (1,args.rows)); sql(alert_insert % (1,args.rows)); sql('ANALYZE events; ANALYZE sigma_alerts;')
    result['fixture_seconds'] = round(time.monotonic()-started,2)
    queries = {}
    for table, oldkey, key, heavy, agent in [('events','ts','created_at','raw',"md5('7')::uuid"),('sigma_alerts','timestamp','COALESCE(created_at,timestamp)','context_data',"md5('7')")]:
        for variant, extra in [('first',''),('agent',f' AND agent_id={agent}'),('deep','')]:
            fence = f"{key} BETWEEN '2026-09-01' AND '2026-10-10'"
            offset = 500000 if variant=='deep' else 0
            # Anchor represents the same historical depth; IDs break timestamp ties.
            seek = f" AND ({key},id) < ('2026-10-08 10:06:40+00','ffffffff-ffff-ffff-ffff-ffffffffffff')" if variant=='deep' else ''
            old = f'SELECT id,{oldkey},{heavy} FROM {table} WHERE {oldkey} BETWEEN \'2026-09-01\' AND \'2026-10-10\'{extra} ORDER BY {oldkey} DESC LIMIT 25 OFFSET {offset}'
            new = f'SELECT id,{key} AS created_at FROM {table} WHERE {fence}{extra}{seek} ORDER BY {key} DESC,id DESC LIMIT 26'
            queries[table+'/'+variant] = (old,new)
            result['queries'][table+'/'+variant] = {'before':sample(old)}
        result['queries'][table+'/legacy_count'] = {'before':sample(f"SELECT count(*) FROM {table} WHERE {oldkey} BETWEEN '2026-09-01' AND '2026-10-10'")}
    def writes():
        out = {}
        for table, insert in [('events',event_insert),('sigma_alerts',alert_insert)]:
            times=[]
            for _ in range(3):
                raw=sql('BEGIN; EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) '+insert % (args.rows+1,args.rows+10000)+'; ROLLBACK;')
                times.append(json.loads(raw)[0]['Execution Time'])
            out[table]=sorted(times)[1]
        return out
    result['insert_10000_before_ms']=writes()
    indexes = [
      'CREATE INDEX CONCURRENTLY idx_events_page_created_id ON events(created_at DESC,id DESC)',
      'CREATE INDEX CONCURRENTLY idx_events_page_agent_created_id ON events(agent_id,created_at DESC,id DESC)',
      'CREATE INDEX CONCURRENTLY idx_sigma_alerts_page_created_id ON sigma_alerts(COALESCE(created_at,timestamp) DESC,id DESC)',
      'CREATE INDEX CONCURRENTLY idx_sigma_alerts_page_agent_created_id ON sigma_alerts(agent_id,COALESCE(created_at,timestamp) DESC,id DESC)',
    ]
    for index in indexes: sql(index)
    sql('ANALYZE events; ANALYZE sigma_alerts;')
    for key, (_,query) in queries.items():
        result['queries'][key]['after']=sample(query)
        result['queries'][key]['after_sql']=query
    result['insert_10000_after_ms']=writes()
    result['candidate_indexes']=indexes
    Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'report':args.output,'rows_per_table':args.rows,'queries':{key:{phase:round(v['median_execution_ms'],3) for phase,v in value.items() if isinstance(v,dict)} for key,value in result['queries'].items()},'write_before':result['insert_10000_before_ms'],'write_after':result['insert_10000_after_ms']},indent=2))
finally:
    sql('DROP DATABASE ' + name + ' WITH (FORCE)', 'postgres')
