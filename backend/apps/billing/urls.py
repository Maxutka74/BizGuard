from django.urls import path

from .views import BillingProfileView, CheckoutView, CompleteCheckoutView

urlpatterns = [
    path("profile", BillingProfileView.as_view(), name="billing-profile"),
    path("checkout", CheckoutView.as_view(), name="billing-checkout"),
    path("complete", CompleteCheckoutView.as_view(), name="billing-complete"),
]
