from django import template


register=template.Library()


def Button_Color(type):
    if type == "active":
        result = "primary"
    else:
        result = "danger"
    return result

@register.simple_tag
def Color_select_HSM_Status(Status):
    Color = Button_Color(Status)
    return Color
