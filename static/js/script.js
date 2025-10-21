document.addEventListener("DOMContentLoaded", function() {
    // --- Flash Messages Auto-Hide ---
    const flashes = document.querySelectorAll(".flash");
    flashes.forEach(flash => {
        setTimeout(() => {
            flash.style.transition = "opacity 0.5s ease, transform 0.5s ease";
            flash.style.opacity = "0";
            flash.style.transform = "translateY(-10px)";
            setTimeout(() => flash.remove(), 500);
        }, 3000);
    });

    // --- Bootstrap Tooltips ---
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // --- Bulk Delete with Modal ---
    const bulkForm = document.getElementById('bulk-delete-form');
    const selectAll = document.getElementById('select-all');
    const deleteBtn = document.getElementById('delete-selected');
    const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    const modalBodyText = document.getElementById('modal-body-text');

    function updateDeleteButtonText() {
        const count = document.querySelectorAll('input[name="student_ids"]:checked').length;
        deleteBtn.textContent = count > 0 ? `Delete Selected (${count})` : 'Delete Selected';
    }

    if(selectAll) {
        selectAll.addEventListener('change', function() {
            let checkboxes = document.querySelectorAll('input[name="student_ids"]');
            checkboxes.forEach(cb => cb.checked = this.checked);
            updateDeleteButtonText();
        });
    }

    const checkboxes = document.querySelectorAll('input[name="student_ids"]');
    checkboxes.forEach(cb => cb.addEventListener('change', updateDeleteButtonText));

    if(deleteBtn && bulkForm) {
        deleteBtn.addEventListener('click', function() {
            const count = document.querySelectorAll('input[name="student_ids"]:checked').length;
            if(count === 0){
                alert('Please select at least one student to delete.');
                return;
            }
            modalBodyText.textContent = `Are you sure you want to delete ${count} student(s)? This action cannot be undone.`;
        });

        if(confirmDeleteBtn){
            confirmDeleteBtn.addEventListener('click', function() {
                bulkForm.submit();
            });
        }
    }
});
