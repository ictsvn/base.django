# https://stackoverflow.com/a/26469873/11225821
def getvars(request):
    """
    Builds a GET variables string to be uses in template links like pagination
    when persistence of the GET vars is needed.
    """
    variables = request.GET.copy()

    if 'page' in variables:
        del variables['page']
    if variables.urlencode():
        return {'getvars': f'&{variables.urlencode()}'}
    else:
        return {'getvars': ''}
