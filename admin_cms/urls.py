from django.conf.urls import url
from . import views

app_name = 'admin_cms'

urlpatterns = [
      # login sign up
      url(r'^new_admin/', view=views.create_new_admin, name="new_admin"),
      url(r'^admin-email-verify', view=views.admin_email_verify, name="admin_email_verify"),
      url(r'^login/', view=views.login_view, name="admin_login"),
      url(r'^change_password/', view=views.changepassword,name="changepassword"),

      # customer cms
      url(r'^get_all_customer', view=views.list_all_customer, name="get_all_customer"),
      url(r'^get_customer', view=views.get_customer_detail, name="get_customer_detail"),
      url(r'^customer-status-list', view=views.customer_status_list, name="customer_status_list"),
      url(r'^customer-status-change', view=views.customer_status_change, name="customer_status_change"),
      url(r'^delete-customer', view=views.delete_customer, name="delete-customer"),
      url(r'^disable_user_2fa', view=views.disble_user_2fa, name="disble_user_2fa-customer"),
      
     
      url(r'^get-contact-us', view=views.get_contact_us_detail, name="get_contact_us_detail"),
      url(r'^contact-us-status-change', view=views.contact_us_status_change, name="contact_us_status_change"),
      
      #admin cms
      url(r'^get_all_admins', view=views.list_all_admins, name="list_all_admins"),
      url(r'^delete-admin', view=views.delete_admin, name="delete-admin")
]