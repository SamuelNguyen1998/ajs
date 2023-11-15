from st2common.runners.base_action import Action
from util.awxclient import AwxClient
from util.common import buildPayload

class Interrupt(Action):
    def run(self, **kwargs):

        awxclient = AwxClient(self.config, kwargs, self.logger)

        # get the ID associated with the job template and POST parameters
        tmp_id = -1
        if kwargs.get("job_template_object_id"):
            tmp_id = kwargs["job_template_object_id"]
        else:
            param = {}
            if kwargs.get("job_template_organization"):
                param["organization"] = kwargs["job_template_organization"]
            if kwargs.get("job_template_project"):
                param["project"] = kwargs["job_template_project"]
            tmp_id = awxclient.getObjectID("/api/v2/job_templates/",
                        kwargs.get("job_template_name"), **param)

        #Print sent json string
        self.logger.debug('Job Template Object ID: "%s"\n' % (tmp_id))

        #Send a HTTP POST request
        payload = buildPayload(self.config, kwargs, self.logger)
        self.logger.debug('Encoded payload: "%s"\n' % (payload))
        res = awxclient.post(
            "/api/v2/job_templates/" + str(tmp_id) + "/launch/", payload)

        #Print output of request
        self.logger.debug('Get Response "%s"' % (res.content))

        #Raise error if status not ok
        if (not res.ok):
            res.raise_for_status()

        res = awxclient.getJobTemplateResult(res.json()['id'])

        return res.json()
