from django import template
import hashlib
from .API_Request import * 
import requests
import os
# Hedef URL
register=template.Library()

@register.simple_tag
def TwoStatus(Status):
    if Status == 'Disable':
        result = 'danger'
    elif Status == 'Enable':
        result = 'primary'
    return result


@register.simple_tag
def Reverse(Statuss):
    if Statuss == 'Disable':
        result = 'Enable'
    elif Statuss == 'Enable':
        result = 'Disable'
    return result


@register.simple_tag
def TwoStatus_reverse(Status):
    if Status == 'Disable':
        result = 'primary'
    elif Status == 'Enable':
        result = 'danger'
    return result


@register.simple_tag
def TwoStatus_message(Status):
    if Status == 'Disable':
        result = 'Activate the Two Factor feature'
    elif Status == 'Enable':
        result = 'Disable the Two Factor feature'
    return result

@register.simple_tag
def MultiStatus_message(Status):
    if Status == 'Disable':
        result = 'Activate the Multi Factor feature'
    elif Status == 'Enable':
        result = 'Disable the Multi Factor feature'
    return result