from FirewallRules.buildFirewallRulesWeb import pushrulestofirewall
from contextlib import redirect_stdout
from celery import shared_task


@shared_task
def redirectedbuildRulefromDBDirect(change_id, change_number, username, password):
    log_file = 'FirewallRules/logs/'+str(change_number)+'.txt'
    with open(log_file, 'w') as f:
       with redirect_stdout(f):
            pushrulestofirewall(username, password,change_id)
            
    

