from django.urls import path

from .views import BillingProfileView, CheckoutView, CompleteCheckoutView, ReissueLegacyKeyView

urlpatterns = [
    path("profile", BillingProfileView.as_view(), name="billing-profile"),
    path("checkout", CheckoutView.as_view(), name="billing-checkout"),
    path("complete", CompleteCheckoutView.as_view(), name="billing-complete"),
    path("orders/<uuid:order_id>/reissue-key", ReissueLegacyKeyView.as_view(), name="billing-reissue-key"),
]
