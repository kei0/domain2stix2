from stix2 import Malware
from stix2 import Indicator
from stix2 import Relationship
from stix2 import Bundle
import json

malware = Malware(name="myTestPhishingDomains",
 is_family=False)
malObj = malware.serialize(pretty=True)
malJs = json.loads(malObj)
malId = malJs['id']

ind_rel = []
domains = open('domains.txt', 'r')
for domain in domains:
 domain = domain.rstrip('\n')
 indicator = Indicator(name="Phshing Domain",
  pattern = "[domain-name:value='" + domain + "']",
  pattern_type = "stix")
 indObj = indicator.serialize(pretty=True)
 indJs = json.loads(indObj)
 indId = indJs['id']
 ind_rel.append(indJs)
 
 relationship = Relationship(relationship_type='indicates',
  source_ref=indId,
  target_ref=malId)
 relObj = relationship.serialize(pretty=True)
 relJs = json.loads(relObj)
 ind_rel.append(relJs)

domains.close()

bundle = Bundle(malware,ind_rel)
print(bundle.serialize(pretty=True))
