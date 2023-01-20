load("json.star", "json")
load("logging.star", "log")
load("time.star", "time")

def apply(metric):

    metrics = processSarif(metric)
    return metrics

def addIfNotNullField(key, value, metric):
    if value:
        metric.fields[key] = value

def addIfNotNullTag(metric, key, value):
    if value:
        metric.tags[key] = value

def processSarif(metric):      
    metrics =  []
    # Loop over the json array stored into the field 
    j = json.decode(metric.fields.get("value"))

    for run in j["runs"]:        
        amaroq_run_metric = Metric("amaroq_runs")

        amaroq = run['properties']['amaroq']                
        amaroq_timestamp = amaroq.get('timestamp')
        newtime = time.parse_time(amaroq_timestamp, format="2006-01-02T15:04:05Z").unix_nano
        amaroq_run_metric.time = newtime                        
        amaroq_organization_id = str(amaroq['organizationId'])
        amaroq_project_id = str(amaroq['projectId'])
        
        #amaroq_run_metric.tags['version'] = amaroq['version']
        #amaroq_run_metric.tags['timestamp'] = amaroq_timestamp
        amaroq_run_metric.tags['id'] = amaroq['id']
        amaroq_run_metric.tags['organizationId'] = amaroq_organization_id
        amaroq_run_metric.tags['projectId'] = amaroq_project_id              

        summary = amaroq["summary"]
        amaroq_run_metric.fields['critical'] = summary['critical']
        amaroq_run_metric.fields['high'] = summary['high']
        amaroq_run_metric.fields['medium'] = summary['medium']
        amaroq_run_metric.fields['low'] = summary['low']
        total = summary['critical'] + summary['high'] + summary['medium'] + summary['low']
        amaroq_run_metric.fields['total'] = str(total)
        amaroq_run_metric.fields['suppressed'] = summary['suppressed']

        amaroq_run_metric.fields['new'] = summary['new']        
        amaroq_run_metric.fields['unchanged'] = summary['unchanged']
        amaroq_run_metric.fields['updated'] = summary['updated']
        amaroq_run_metric.fields['absent'] = summary['absent']
        

        # parse tool driver
        tool = run.get('tool')
        driver = tool.get('driver')
        name = driver.get('name')
        version = driver.get('version')
        amaroq_run_metric.tags['tool_name'] = name
        #amaroq_run_metric.tags['tool_version'] = version
        

        # add per run amaroq metrics
        metrics.append(amaroq_run_metric)

        results = run['results']
        for result in results:
            current_metric = Metric("amaroq_results")
            current_metric.time = newtime                        
            
            rule_id = result['ruleId']
            message = result.get('message')
            baseline_state = result['baselineState']

            #current_metric.tags['version'] = amaroq['version']
            current_metric.tags['amaroq_timestamp'] = amaroq_timestamp
            current_metric.tags['amaroq_id'] = amaroq['id']
            current_metric.tags['organizationId'] = amaroq_organization_id
            current_metric.tags['projectId'] = amaroq_project_id 

            # add tool details
            current_metric.tags['guid'] = result.get('guid')
            current_metric.tags['correlationGuid'] = result.get('correlationGuid')

            lastfingerprint = None
            fingerprints = result.get('fingerprints')
            if fingerprints:
                keys = fingerprints.keys()
                for fingerprint in keys:
                    current_metric.fields[fingerprint] = fingerprints[fingerprint]
                    lastfingerprint = fingerprints[fingerprint]
            
            if not lastfingerprint:
                partialFingerprint = result.get('partialFingerprints')
                if partialFingerprint:
                    lastfingerprint = result['partialFingerprints']['id']
                    current_metric.fields['partialFingerprints_id'] = lastfingerprint #fail if null                    
            
            # needed for primary key
            current_metric.tags['lastFingerprint'] = lastfingerprint #fail if null

            #current_metric.tags['tool_name'] = name
            #current_metric.tags['tool_version'] = version             
            #current_metric.tags['rule_id'] = rule_id
            #current_metric.tags['level'] = level
            #current_metric.tags['baseline_state'] = baseline_state
            
            # nullable tags
            #addIfNotNullTag('rule_index', result.get('rule_index'), current_metric)
            #addIfNotNullTag('kind', result.get('kind'), current_metric)
            #addIfNotNullTag('rank', result.get('rank'), current_metric)            
            
            # if message:
            #     addIfNotNullTag('text', message.get('text'), current_metric)                

            provenance = result.get('provenance')            
            # if provenance:
            #     addIfNotNullTag('first_detection_time_utc', provenance.get('first_detection_time_utc'), current_metric)            
            #     addIfNotNullTag('first_detection_run_guid', provenance.get('first_detection_run_guid'), current_metric)            
            #     addIfNotNullTag('last_detection_time_utc', provenance.get('last_detection_time_utc'), current_metric)            
            #     addIfNotNullTag('last_detection_run_guid', provenance.get('last_detection_run_guid'), current_metric)            

            # TODO
            # suppressions = result.get('suppressions')            
            # current_metric.fields['suppressions'] = suppressions
            
            #### Fields
            current_metric.fields['rule_id'] = rule_id
            #current_metric.fields['level'] = level
            current_metric.fields['baseline_state'] = baseline_state
            #current_metric.fields['tool_version'] = version             
            
            # nullable fields
            addIfNotNullField('tool_version', result.get('tool_version'), current_metric)
            addIfNotNullField('level', result.get('level'), current_metric)
            addIfNotNullField('rule_index', result.get('rule_index'), current_metric)
            addIfNotNullField('kind', result.get('kind'), current_metric)
            addIfNotNullField('rank', result.get('rank'), current_metric)            

            if message:
                addIfNotNullField('text', message.get('text'), current_metric)                            

            if provenance:
                addIfNotNullField('first_detection_time_utc', provenance.get('first_detection_time_utc'), current_metric)            
                addIfNotNullField('first_detection_run_guid', provenance.get('first_detection_run_guid'), current_metric)            
                addIfNotNullField('last_detection_time_utc', provenance.get('last_detection_time_utc'), current_metric)            
                addIfNotNullField('last_detection_run_guid', provenance.get('last_detection_run_guid'), current_metric)            
            # TODO
            # suppressions = result.get('suppressions')            
            # current_metric.fields['suppressions'] = suppressions

            
            # add per result tool metrics
            metrics.append(current_metric)

            ## stateful metrics
            result_stateful_metric = Metric("amaroq_results_stateful")
            statictime = time.parse_time("2023-01-19T15:04:05Z", format="2006-01-02T15:04:05Z").unix_nano
            result_stateful_metric.time = statictime                        
            
            rule_id = result['ruleId']
            message = result.get('message')
            baseline_state = result['baselineState']

            #current_metric.tags['version'] = amaroq['version']
            #result_stateful_metric.tags['amaroq_timestamp'] = amaroq_timestamp
            #result_stateful_metric.tags['amaroq_id'] = amaroq['id']
            result_stateful_metric.tags['organizationId'] = amaroq_organization_id
            result_stateful_metric.tags['projectId'] = amaroq_project_id 

            # add tool details
            #result_stateful_metric.tags['guid'] = result.get('guid')
            result_stateful_metric.tags['correlationGuid'] = result.get('correlationGuid')

            lastfingerprint = None
            fingerprints = result.get('fingerprints')
            if fingerprints:
                keys = fingerprints.keys()
                for fingerprint in keys:
                    result_stateful_metric.fields[fingerprint] = fingerprints[fingerprint]
                    lastfingerprint = fingerprints[fingerprint]
            
            if not lastfingerprint:
                partialFingerprint = result.get('partialFingerprints')
                if partialFingerprint:
                    lastfingerprint = result['partialFingerprints']['id']
                    result_stateful_metric.fields['partialFingerprints_id'] = lastfingerprint #fail if null                    
            
            result_stateful_metric.fields['lastFingerprint'] = lastfingerprint #fail if null
            
            # TODO
            # suppressions = result.get('suppressions')            
            # result_stateful_metric.fields['suppressions'] = suppressions
            
            #### Fields
            result_stateful_metric.fields['rule_id'] = rule_id
            result_stateful_metric.fields['baseline_state'] = baseline_state
            
            # nullable fields
            addIfNotNullField('tool_version', result.get('tool_version'), result_stateful_metric)
            addIfNotNullField('level', result.get('level'), result_stateful_metric)
            addIfNotNullField('rule_index', result.get('rule_index'), result_stateful_metric)
            addIfNotNullField('kind', result.get('kind'), result_stateful_metric)
            addIfNotNullField('rank', result.get('rank'), result_stateful_metric)            

            if message:
                addIfNotNullField('text', message.get('text'), result_stateful_metric)                            

            if provenance:
                addIfNotNullField('first_detection_time_utc', provenance.get('first_detection_time_utc'), result_stateful_metric)            
                addIfNotNullField('first_detection_run_guid', provenance.get('first_detection_run_guid'), result_stateful_metric)            
                addIfNotNullField('last_detection_time_utc', provenance.get('last_detection_time_utc'), result_stateful_metric)            
                addIfNotNullField('last_detection_run_guid', provenance.get('last_detection_run_guid'), result_stateful_metric)            
            # TODO
            # suppressions = result.get('suppressions')            
            # result_stateful_metric.fields['suppressions'] = suppressions

            
            # add per result tool metrics
            metrics.append(result_stateful_metric)



    return metrics

