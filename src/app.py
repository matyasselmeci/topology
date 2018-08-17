"""
Application File
"""
import datetime
from typing import List

import flask
import flask.logging
from flask import Flask, Response, request, render_template, make_response
import logging
import os
import re
import sys
import urllib.parse

from webapp import default_config
from webapp.common import gen_id, to_xml_bytes, Filters
from webapp.forms import DowntimeResourceSelectForm, GenerateDowntimeForm
from webapp.models import GlobalData
from webapp.topology import GRIDTYPE_1, GRIDTYPE_2


class InvalidArgumentsError(Exception): pass

def _verify_config(cfg):
    if not cfg["NO_GIT"]:
        ssh_key = cfg["GIT_SSH_KEY"]
        if not ssh_key:
            raise ValueError("GIT_SSH_KEY must be specified if using Git")
        elif not os.path.exists(ssh_key):
            raise FileNotFoundError(ssh_key)
        else:
            st = os.stat(ssh_key)
            if st.st_uid != os.getuid() or (st.st_mode & 0o7777) not in (0o700, 0o600, 0o400):
                raise PermissionError(ssh_key)


default_authorized = False

app = Flask(__name__)
app.config.from_object(default_config)
app.config.from_pyfile("config.py", silent=True)
if "TOPOLOGY_CONFIG" in os.environ:
    app.config.from_envvar("TOPOLOGY_CONFIG", silent=False)
_verify_config(app.config)
if "AUTH" in app.config:
    if app.debug:
        default_authorized = app.config["AUTH"]
    else:
        print("ignoring AUTH option when FLASK_ENV != development", file=sys.stderr)
if not app.config.get("SECRET_KEY"):
    app.config["SECRET_KEY"] = "this is not very secret"
### Replace previous with this when we want to add CSRF protection
#     if app.debug:
#         app.config["SECRET_KEY"] = "this is not very secret"
#     else:
#         raise Exception("SECRET_KEY required when FLASK_ENV != development")

global_data = GlobalData(app.config)


@app.route('/')
def homepage():

    return render_template('homepage.html')

@app.route('/map/iframe')
def map():
    @app.template_filter()
    def encode(text):
        """Convert a partial unicode string to full unicode"""
        return text.encode('utf-8', 'surrogateescape').decode('utf-8')
    rgsummary = global_data.get_topology().get_resource_summary()

    return render_template('iframe.html', resourcegroups=rgsummary["ResourceSummary"]["ResourceGroup"])


@app.route('/schema/<xsdfile>')
def schema(xsdfile):
    if xsdfile in ["vosummary.xsd", "rgsummary.xsd", "rgdowntime.xsd", "miscuser.xsd", "miscproject.xsd"]:
        with open("schema/" + xsdfile, "r") as xsdfh:
            return Response(xsdfh.read(), mimetype="text/xml")
    else:
        flask.abort(404)


@app.route('/miscuser/xml')
def miscuser_xml():
    return Response(to_xml_bytes(global_data.get_contacts_data().get_tree(_get_authorized())),
                    mimetype='text/xml')


@app.route('/miscproject/xml')
def miscproject_xml():
    return Response(to_xml_bytes(global_data.get_projects()), mimetype='text/xml')


@app.route('/vosummary/xml')
def vosummary_xml():
    return _get_xml_or_fail(global_data.get_vos_data().get_tree, request.args)


@app.route('/rgsummary/xml')
def rgsummary_xml():
    return _get_xml_or_fail(global_data.get_topology().get_resource_summary, request.args)


@app.route('/rgdowntime/xml')
def rgdowntime_xml():
    return _get_xml_or_fail(global_data.get_topology().get_downtimes, request.args)


@app.route('/downtime_resource_select')
def downtime_resource_select():
    path = "downtime_resource_select"
    template = f"{path}_form.html"

    form = DowntimeResourceSelectForm(request.form)
    topo = global_data.get_topology()
    form.facility.choices = _make_choices(topo.resource_names_by_facility.keys())

    facility = request.args.get("facility", "")
    if facility:
        resource_names = topo.resource_names_by_facility.get(facility)
        if not resource_names:
            return make_response((f"""
Missing or invalid facility. <a href="/{path}">Select a facility.</a>
""", 400))
        form.facility.data = facility
        form.resource.choices = _make_choices(resource_names)
        return render_template(template, form=form, facility=facility)
    return render_template(template, form=form)


@app.route("/generate_downtime", methods=["GET", "POST"])
def generate_downtime():
    path = "generate_downtime"
    template = f"{path}_form.html"

    form = GenerateDowntimeForm(request.form)
    topo = global_data.get_topology()

    facility = request.args.get("facility")
    if not facility or facility not in topo.resource_names_by_facility:
        return make_response((f"""
Missing or invalid facility. <a href="/{path}">Select a facility.</a>
""", 400))
    resource = request.args.get("resource")
    resource_names = topo.resource_names_by_facility[facility]
    if not resource or not resource_names or resource not in resource_names:
        return make_response((f"""
Missing or invalid resource in facility {flask.escape(facility)}.
<a href="/{path}?facility={urllib.parse.quote(facility)}">Select a resource</a>
or <a href="/{path}">select another facility.</a>
""", 400))

    form.resource.data = resource

    try:
        form.services.choices = _make_choices(topo.service_names_by_resource[resource])
    except (KeyError, IndexError):  # shouldn't happen but deal with anyway
        return make_response((f"""
Missing or invalid services in resource {flask.escape(resource)}.
<a href="/{path}?facility={urllib.parse.quote(facility)}">Select another resource</a>
or <a href="/{path}">select another facility.</a>
""", 400))

    if not form.validate_on_submit():
        return render_template(template, form=form, resource=resource, facility=facility)

    filepath = "topology/" + topo.downtime_path_by_resource[resource]
    # ^ filepath relative to the root of the topology repo checkout
    filename = os.path.basename(filepath)

    # Add github edit URLs or directory URLs for the repo, if we can.
    edit_url = site_dir_url = ""
    if re.match("http(s?)://github.com", global_data.topology_data_repo):
        site_dir_url = "{0}/tree/{1}/{2}".format(global_data.topology_data_repo,
                                                 urllib.parse.quote(global_data.topology_data_branch),
                                                 urllib.parse.quote(os.path.dirname(filepath)))
        if os.path.exists(os.path.join(global_data.topology_dir, topo.downtime_path_by_resource[resource])):
            edit_url = "{0}/edit/{1}/{2}".format(global_data.topology_data_repo,
                                                 urllib.parse.quote(global_data.topology_data_branch),
                                                 urllib.parse.quote(filepath))

    yaml = form.get_yaml()

    return render_template(
        template, form=form, yaml=yaml, resource=resource, filepath=filepath,
        filename=filename, facility=facility, edit_url=edit_url,
        site_dir_url=site_dir_url)


def _make_choices(iterable):
    return [(x.encode("utf-8", "surrogateescape").decode(), x.encode("utf-8", "surrogateescape").decode())
            for x in sorted(iterable)]


def get_filters_from_args(args) -> Filters:
    filters = Filters()
    def filter_value(filter_key):
        filter_value_key = filter_key + "_value"
        if filter_key in args:
            filter_value_str = args.get(filter_value_key, "")
            if filter_value_str == "0":
                return False
            elif filter_value_str == "1":
                return True
            else:
                raise InvalidArgumentsError("{0} must be 0 or 1".format(filter_value_key))
    filters.active = filter_value("active")
    filters.disable = filter_value("disable")
    filters.oasis = filter_value("oasis")

    if "gridtype" in args:
        gridtype_1, gridtype_2 = args.get("gridtype_1", ""), args.get("gridtype_2", "")
        if gridtype_1 == "on" and gridtype_2 == "on":
            pass
        elif gridtype_1 == "on":
            filters.grid_type = GRIDTYPE_1
        elif gridtype_2 == "on":
            filters.grid_type = GRIDTYPE_2
        else:
            raise InvalidArgumentsError("gridtype_1 or gridtype_2 or both must be \"on\"")
    if "service_hidden_value" in args:  # note no "service_hidden" args
        if args["service_hidden_value"] == "0":
            filters.service_hidden = False
        elif args["service_hidden_value"] == "1":
            filters.service_hidden = True
        else:
            raise InvalidArgumentsError("service_hidden_value must be 0 or 1")
    if "downtime_attrs_showpast" in args:
        # doesn't make sense for rgsummary but will be ignored anyway
        try:
            v = args["downtime_attrs_showpast"]
            if v == "all":
                filters.past_days = -1
            elif not v:
                filters.past_days = 0
            else:
                filters.past_days = int(args["downtime_attrs_showpast"])
        except ValueError:
            raise InvalidArgumentsError("downtime_attrs_showpast must be an integer, \"\", or \"all\"")
    if "has_wlcg" in args:
        filters.has_wlcg = True

    # 2 ways to filter by a key like "facility", "service", "sc", "site", etc.:
    # - either pass KEY_1=on, KEY_2=on, etc.
    # - pass KEY_sel[]=1, KEY_sel[]=2, etc. (multiple KEY_sel[] args).
    for filter_key, filter_list, description in [
        ("facility", filters.facility_id, "facility ID"),
        ("rg", filters.rg_id, "resource group ID"),
        ("service", filters.service_id, "service ID"),
        ("sc", filters.support_center_id, "support center ID"),
        ("site", filters.site_id, "site ID"),
        ("vo", filters.vo_id, "VO ID"),
        ("voown", filters.voown_id, "VO owner ID"),
    ]:
        if filter_key in args:
            pat = re.compile(r"{0}_(\d+)".format(filter_key))
            arg_sel = "{0}_sel[]".format(filter_key)
            for k, v in args.items():
                if k == arg_sel:
                    try:
                        filter_list.append(int(v))
                    except ValueError:
                        raise InvalidArgumentsError("{0}={1}: must be int".format(k,v))
                elif pat.match(k):
                    m = pat.match(k)
                    filter_list.append(int(m.group(1)))
            if not filter_list:
                raise InvalidArgumentsError("at least one {0} must be specified".format(description))

    if filters.voown_id:
        filters.populate_voown_name(global_data.get_vos_data().get_vo_id_to_name())

    return filters


def _get_xml_or_fail(getter_function, args):
    try:
        filters = get_filters_from_args(args)
    except InvalidArgumentsError as e:
        return Response("Invalid arguments: " + str(e), status=400)
    return Response(
        to_xml_bytes(getter_function(_get_authorized(), filters)),
        mimetype="text/xml"
    )


def _get_authorized():
    """
    Determine if the client is authorized

    returns: True if authorized, False otherwise
    """
    # Loop through looking for all of the creds
    for key, value in request.environ.items():
        if key.startswith('GRST_CRED_AURI_') and value.startswith("dn:"):

            # HTTP unquote the DN:
            client_dn = urllib.parse.unquote_plus(value)

            # Get list of authorized DNs
            authorized_dns = global_data.get_dns()

            # Authorized dns should be a set, or dict, that supports the "in"
            if client_dn[3:] in authorized_dns: # "dn:" is at the beginning of the DN
                return True     

    # If it gets here, then it is not authorized
    return default_authorized


if __name__ == '__main__':
    try:
        if sys.argv[1] == "--auth":
            default_authorized = True
    except IndexError: pass
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True, use_reloader=True)
else:
    root = logging.getLogger()
    root.addHandler(flask.logging.default_handler)
